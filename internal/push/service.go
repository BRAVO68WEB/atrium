package push

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

const problemBase = "https://atrium.local/problems/"

// Problem is an RFC 9457 body for the push endpoints.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func (p Problem) Error() string { return p.Detail }

func problem(status int, slug, detail string) Problem {
	defer telemetry.Step("push.problem")()
	return Problem{Type: problemBase + slug, Title: slug, Status: status, Detail: detail}
}

// Service registers authenticator devices. It does not wake them.
type Service struct {
	db    database.SQL
	cfg   *config.Config
	dpop  *service.DPoPService
	now   func() time.Time
	mu    sync.Mutex
	nonce map[string]nonceState
	hits  map[string][]time.Time
}

type nonceState struct {
	value string
	used  bool
}

func NewService(cfg *config.Config, db database.SQL, dpop *service.DPoPService) *Service {
	defer telemetry.Step("push.NewService")()
	return &Service{
		db:    db,
		cfg:   cfg,
		dpop:  dpop,
		now:   time.Now,
		nonce: map[string]nonceState{},
		hits:  map[string][]time.Time{},
	}
}

func (s *Service) issuer() string {
	defer telemetry.Step("push.Service.issuer")()
	return strings.TrimRight(s.cfg.Security.Issuer, "/")
}

func (s *Service) Discovery() map[string]any {
	defer telemetry.Step("push.Service.Discovery")()
	base := s.issuer()
	modes := deliveryModes(s.cfg)
	doc := map[string]any{
		"registration_endpoint":        base + "/push/register",
		"delivery_modes_supported":     modes,
		"interaction_type_supported":   []string{"boolean", "number_choose", "input_manual"},
		"minimum_interaction_type":     s.cfg.Push.MinimumInteractionType,
		"registration_token_ttl":       s.cfg.Push.RegistrationTokenTTL,
		"signing_alg_values_supported": []string{"ES256"},
		"fallback_order":               modes,
		"client_attestation_required":  s.cfg.Push.ClientAttestation,
		"revocation_endpoint":          base + "/push/revoke",
		"key_rotation_endpoint":        base + "/push/rotate-key",
		"device_management_endpoint":   base + "/push/devices",
		"max_devices_per_user":         s.cfg.Push.MaxDevicesPerUser,
		"push_wait_timeout_seconds":    10,
		"error_response_format":        "application/problem+json",
	}
	if s.cfg.Push.PushEnabled {
		if relay := strings.TrimSpace(s.cfg.Push.RelayEndpoint); relay != "" {
			doc["push_relay_endpoint"] = relay
		}
	}
	return doc
}

// Enrollment is what the browser page shows. The token sits in the URL fragment.
type Enrollment struct {
	Token string
	URL   string
	QR    string
}

func (s *Service) IssueEnrollment(userID, clientID string, sign func(claims jwt.MapClaims) (string, error)) (Enrollment, error) {
	defer telemetry.Step("push.Service.IssueEnrollment")()
	jti := uuid.NewString()
	exp := s.now().Add(time.Duration(s.cfg.Push.RegistrationTokenTTL) * time.Second)
	claims := jwt.MapClaims{
		"iss": s.issuer(),
		"sub": userID,
		"aud": s.issuer() + "/push/register",
		"exp": exp.Unix(),
		"iat": s.now().Unix(),
		"jti": jti,
	}
	if clientID != "" {
		claims["client_id"] = clientID
	}
	raw, err := sign(claims)
	if err != nil {
		return Enrollment{}, err
	}
	if _, err := s.db.Exec(`INSERT INTO push_registration_tokens (jti, user_id, client_id, expires_at, used) VALUES (?, ?, ?, ?, 0)`,
		jti, userID, clientID, exp.UTC().Format(time.RFC3339)); err != nil {
		return Enrollment{}, err
	}
	page := s.issuer() + "/push/enroll#" + raw
	png, err := qrcode.Encode(page, qrcode.Medium, 256)
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Token: raw, URL: page, QR: base64.StdEncoding.EncodeToString(png)}, nil
}

type registerRequest struct {
	RegistrationToken string         `json:"registration_token"`
	PublicKey         map[string]any `json:"public_key"`
	InteractionTypes  []string       `json:"interaction_types"`
	PushAddress       string         `json:"push_address"`
	Platform          string         `json:"platform"`
	Attestation       string         `json:"attestation"`
	ReplacesDeviceID  string         `json:"replaces_device_id"`
}

type Registered struct {
	DeviceID   string `json:"device_id"`
	Credential string `json:"device_credential"`
	Ref        string `json:"registration_ref"`
	ExpiresIn  int    `json:"expires_in"`
}

func (s *Service) Register(ip string, body []byte, keyfunc jwt.Keyfunc) (Registered, error) {
	defer telemetry.Step("push.Service.Register")()
	if s.limited(ip) {
		return Registered{}, problem(http.StatusTooManyRequests, "rate_limited", "too many registration attempts")
	}
	var req registerRequest
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.RegistrationToken) == "" {
		return Registered{}, problem(http.StatusBadRequest, "invalid_registration_token", "registration token is required")
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(req.RegistrationToken, claims, keyfunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Registered{}, problem(http.StatusBadRequest, "registration_token_expired", "registration token is expired")
		}
		return Registered{}, problem(http.StatusBadRequest, "invalid_registration_token", "registration token is invalid")
	}
	if !parsed.Valid {
		return Registered{}, problem(http.StatusBadRequest, "invalid_registration_token", "registration token is invalid")
	}
	if claims["iss"] != s.issuer() || claims["aud"] != s.issuer()+"/push/register" {
		return Registered{}, problem(http.StatusBadRequest, "invalid_registration_token", "registration token audience is wrong")
	}
	jti, _ := claims["jti"].(string)
	userID, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	var storedUser, expiresAt string
	var used int
	err = s.db.QueryRow(`SELECT user_id, expires_at, used FROM push_registration_tokens WHERE jti = ?`, jti).Scan(&storedUser, &expiresAt, &used)
	if err != nil || storedUser != userID {
		return Registered{}, problem(http.StatusBadRequest, "invalid_registration_token", "registration token is unknown")
	}
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	if s.now().After(exp) {
		return Registered{}, problem(http.StatusBadRequest, "registration_token_expired", "registration token is expired")
	}
	if used != 0 {
		return Registered{}, problem(http.StatusBadRequest, "registration_token_already_used", "registration token was already redeemed")
	}
	if !contains(req.InteractionTypes, s.cfg.Push.MinimumInteractionType) {
		return Registered{}, problem(http.StatusBadRequest, "interaction_type_unsupported", "device does not support the minimum interaction type")
	}
	if s.cfg.Push.ClientAttestation && strings.TrimSpace(req.Attestation) == "" {
		return Registered{}, problem(http.StatusBadRequest, "attestation_missing", "attestation is required")
	}
	pub, jkt, jwkText, err := canonicalKey(req.PublicKey, s.dpop)
	if err != nil || pub == nil {
		return Registered{}, problem(http.StatusBadRequest, "invalid_public_key", "public key must be P-256")
	}
	replacing := false
	if strings.TrimSpace(req.ReplacesDeviceID) != "" {
		var owner, replacedStatus string
		err = s.db.QueryRow(`SELECT user_id, status FROM push_devices WHERE id = ?`, req.ReplacesDeviceID).Scan(&owner, &replacedStatus)
		if err != nil || owner != userID || replacedStatus != "active" {
			return Registered{}, problem(http.StatusBadRequest, "unknown_device", "replaced device is not active")
		}
		replacing = true
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM push_devices WHERE user_id = ? AND status = 'active'`, userID).Scan(&n); err != nil {
		return Registered{}, err
	}
	if n >= s.cfg.Push.MaxDevicesPerUser && !replacing {
		return Registered{}, problem(http.StatusForbidden, "device_limit", "device limit reached")
	}
	_, _ = s.db.Exec(`DELETE FROM push_registration_tokens WHERE expires_at < ?`, s.now().UTC().Format(time.RFC3339))
	credential, err := crypto.GenerateToken()
	if err != nil {
		return Registered{}, err
	}
	id := uuid.NewString()
	types, _ := json.Marshal(req.InteractionTypes)
	now := s.now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`UPDATE push_registration_tokens SET used = 1 WHERE jti = ?`, jti); err != nil {
		return Registered{}, err
	}
	if _, err := s.db.Exec(`INSERT INTO push_devices (id, user_id, client_id, jwk, jkt, credential_hash, platform, push_address, interaction_types, attestation, status, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`,
		id, userID, clientID, jwkText, jkt, hashCredential(credential), req.Platform, req.PushAddress, string(types), req.Attestation, now, now); err != nil {
		return Registered{}, err
	}
	if replacing {
		if _, err := s.db.Exec(`UPDATE push_devices SET status = 'revoked', last_used_at = ? WHERE id = ? AND user_id = ? AND status = 'active'`, now, req.ReplacesDeviceID, userID); err != nil {
			return Registered{}, err
		}
		s.cascadeRevoke(req.ReplacesDeviceID)
		s.notify(req.ReplacesDeviceID, "device_revoked", req.ReplacesDeviceID)
	}
	return Registered{DeviceID: id, Credential: credential, Ref: "urn:push-reg:" + id, ExpiresIn: s.cfg.Push.RegistrationTokenTTL}, nil
}

// Device is a row safe to show the signed-in user.
type Device struct {
	ID                string   `json:"device_id"`
	Platform          string   `json:"platform"`
	CreatedAt         string   `json:"created_at"`
	LastUsedAt        string   `json:"last_used_at,omitempty"`
	InteractionTypes  []string `json:"interaction_types"`
	Status            string   `json:"status"`
	IsPrimary         bool     `json:"is_primary"`
	AttestationStatus string   `json:"attestation_status"`
}

func (s *Service) List(userID string) ([]Device, error) {
	defer telemetry.Step("push.Service.List")()
	rows, err := s.db.Query(`SELECT id, COALESCE(platform, ''), created_at, COALESCE(last_used_at, ''), interaction_types, status, COALESCE(is_primary, 0) FROM push_devices WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		var item Device
		var raw string
		var primary int
		if err := rows.Scan(&item.ID, &item.Platform, &item.CreatedAt, &item.LastUsedAt, &raw, &item.Status, &primary); err != nil {
			return nil, err
		}
		item.IsPrimary = primary != 0
		item.AttestationStatus = "not_checked"
		_ = json.Unmarshal([]byte(raw), &item.InteractionTypes)
		out = append(out, item)
	}
	if out == nil {
		out = []Device{}
	}
	return out, rows.Err()
}

type deviceRow struct {
	id          string
	userID      string
	jwk         string
	jkt         string
	hash        string
	status      string
	previousJWK string
	previousJKT string
	graceUntil  string
}

func (s *Service) authenticate(r *http.Request, deviceID, credential string) (deviceRow, error) {
	defer telemetry.Step("push.Service.authenticate")()
	return s.finishAuth(r, deviceID, credential, false)
}

func (s *Service) finishAuth(r *http.Request, deviceID, credential string, allowRevoked bool) (deviceRow, error) {
	defer telemetry.Step("push.Service.finishAuth")()
	var row deviceRow
	err := s.db.QueryRow(`SELECT id, user_id, jwk, jkt, credential_hash, status, COALESCE(previous_jwk, ''), COALESCE(previous_jkt, ''), COALESCE(grace_until, '') FROM push_devices WHERE id = ?`, deviceID).Scan(
		&row.id, &row.userID, &row.jwk, &row.jkt, &row.hash, &row.status, &row.previousJWK, &row.previousJKT, &row.graceUntil)
	active := row.status == "active" || (allowRevoked && row.status == "revoked")
	if err != nil || !active || subtle.ConstantTimeCompare([]byte(row.hash), []byte(hashCredential(credential))) != 1 {
		return deviceRow{}, problem(http.StatusUnauthorized, "invalid_device_credential", "device credential is not valid")
	}
	if err := s.checkNonce(r, deviceID); err != nil {
		return deviceRow{}, err
	}
	if s.dpop == nil || r.Header.Get("DPoP") == "" {
		return deviceRow{}, problem(http.StatusUnauthorized, "dpop_required", "DPoP proof is required")
	}
	proof, err := s.dpop.ValidateDPoPProof(r.Context(), r.Header.Get("DPoP"), r.Method, requestURI(r), "")
	if err != nil || !s.acceptThumbprint(row, proof.JKT) {
		return deviceRow{}, problem(http.StatusUnauthorized, "dpop_required", "DPoP proof does not match the device key")
	}
	return row, nil
}

func (s *Service) acceptThumbprint(row deviceRow, jkt string) bool {
	defer telemetry.Step("push.Service.acceptThumbprint")()
	if jkt == row.jkt {
		if row.previousJKT != "" {
			_, _ = s.db.Exec(`UPDATE push_devices SET previous_jwk = '', previous_jkt = '', grace_until = '' WHERE id = ?`, row.id)
		}
		return true
	}
	if row.previousJKT == "" || jkt != row.previousJKT || row.graceUntil == "" {
		return false
	}
	until, err := time.Parse(time.RFC3339, row.graceUntil)
	return err == nil && s.now().Before(until)
}

func (s *Service) Revoke(r *http.Request, deviceID, credential string) (string, error) {
	defer telemetry.Step("push.Service.Revoke")()
	if s.deviceLimited(deviceID) {
		return "", problem(http.StatusTooManyRequests, "rate_limited", "too many requests for this device")
	}
	row, err := s.finishAuth(r, deviceID, credential, true)
	if err != nil {
		return "", err
	}
	if row.status == "active" {
		if _, err := s.db.Exec(`UPDATE push_devices SET status = 'revoked', last_used_at = ? WHERE id = ?`, s.now().UTC().Format(time.RFC3339), deviceID); err != nil {
			return "", err
		}
		s.cascadeRevoke(deviceID)
		s.notify(deviceID, "device_revoked", deviceID)
	}
	return s.issueNonce(deviceID), nil
}

// RevokeUser revokes every active device for an admin recovery.
func (s *Service) RevokeUser(userID string) (int, error) {
	defer telemetry.Step("push.Service.RevokeUser")()
	rows, err := s.db.Query(`SELECT id FROM push_devices WHERE user_id = ? AND status = 'active'`, userID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	now := s.now().UTC().Format(time.RFC3339)
	for _, id := range ids {
		if _, err := s.db.Exec(`UPDATE push_devices SET status = 'revoked', last_used_at = ? WHERE id = ? AND status = 'active'`, now, id); err != nil {
			return 0, err
		}
		s.cascadeRevoke(id)
		s.notify(id, "device_revoked", id)
	}
	return len(ids), nil
}

// MakePrimary marks one active device and clears the flag on the others.
func (s *Service) MakePrimary(userID, deviceID string) error {
	defer telemetry.Step("push.Service.MakePrimary")()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM push_devices WHERE id = ? AND user_id = ? AND status = 'active'`, deviceID, userID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return problem(http.StatusNotFound, "unknown_device", "device is not active")
	}
	if _, err := s.db.Exec(`UPDATE push_devices SET is_primary = 0 WHERE user_id = ?`, userID); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE push_devices SET is_primary = 1 WHERE id = ? AND user_id = ?`, deviceID, userID)
	return err
}

type rotateRequest struct {
	DeviceID     string         `json:"device_id"`
	NewPublicKey map[string]any `json:"new_public_key"`
	Proof        string         `json:"proof_of_possession"`
	Reason       string         `json:"reason"`
}

func (s *Service) Rotate(r *http.Request, body []byte, credential string) (Registered, string, error) {
	defer telemetry.Step("push.Service.Rotate")()
	var req rotateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return Registered{}, "", problem(http.StatusBadRequest, "invalid_public_key", "rotation body is invalid")
	}
	if s.deviceLimited(req.DeviceID) {
		return Registered{}, "", problem(http.StatusTooManyRequests, "rate_limited", "too many requests for this device")
	}
	row, err := s.authenticate(r, req.DeviceID, credential)
	if err != nil {
		return Registered{}, "", err
	}
	pub, err := publicFromJWKText(row.jwk)
	if err != nil {
		return Registered{}, "", err
	}
	newPub, newJKT, newText, err := canonicalKey(req.NewPublicKey, s.dpop)
	if err != nil || newPub == nil {
		return Registered{}, "", problem(http.StatusBadRequest, "invalid_public_key", "public key must be P-256")
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(req.Proof, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected alg")
		}
		return pub, nil
	})
	if err != nil || !parsed.Valid || claims["jkt"] != newJKT {
		return Registered{}, "", problem(http.StatusUnauthorized, "invalid_proof", "proof of possession does not match the new key")
	}
	credentialNew, err := crypto.GenerateToken()
	if err != nil {
		return Registered{}, "", err
	}
	now := s.now().UTC()
	previousJWK, previousJKT, graceUntil := "", "", ""
	if req.Reason != "compromised" {
		previousJWK = row.jwk
		previousJKT = row.jkt
		graceUntil = now.Add(s.grace()).Format(time.RFC3339)
	}
	if _, err := s.db.Exec(`UPDATE push_devices SET jwk = ?, jkt = ?, credential_hash = ?, previous_jwk = ?, previous_jkt = ?, grace_until = ?, last_used_at = ? WHERE id = ?`,
		newText, newJKT, hashCredential(credentialNew), previousJWK, previousJKT, graceUntil, now.Format(time.RFC3339), row.id); err != nil {
		return Registered{}, "", err
	}
	return Registered{DeviceID: row.id, Credential: credentialNew, Ref: "urn:push-reg:" + row.id, ExpiresIn: s.cfg.Push.RegistrationTokenTTL}, s.issueNonce(row.id), nil
}

func (s *Service) grace() time.Duration {
	defer telemetry.Step("push.Service.grace")()
	seconds := 300
	if s.cfg != nil && s.cfg.Push.GracePeriodSeconds > 0 {
		seconds = s.cfg.Push.GracePeriodSeconds
	}
	return time.Duration(seconds) * time.Second
}

func (s *Service) deviceLimited(deviceID string) bool {
	defer telemetry.Step("push.Service.deviceLimited")()
	if strings.TrimSpace(deviceID) == "" {
		return false
	}
	return s.limited("device:" + deviceID)
}

func (s *Service) checkNonce(r *http.Request, deviceID string) error {
	defer telemetry.Step("push.Service.checkNonce")()
	got := strings.TrimSpace(r.Header.Get("Replay-Nonce"))
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.nonce[deviceID]
	if !ok {
		if got != "" {
			return problem(http.StatusBadRequest, "nonce_replayed", "replay nonce was not issued")
		}
		return nil
	}
	if got == "" || got != state.value || state.used {
		return problem(http.StatusBadRequest, "nonce_replayed", "replay nonce is missing or reused")
	}
	state.used = true
	s.nonce[deviceID] = state
	return nil
}

func (s *Service) issueNonce(deviceID string) string {
	defer telemetry.Step("push.Service.issueNonce")()
	buf := make([]byte, 16)
	_, _ = cryptoRand(buf)
	value := base64.RawURLEncoding.EncodeToString(buf)
	s.mu.Lock()
	s.nonce[deviceID] = nonceState{value: value}
	s.mu.Unlock()
	return value
}

func (s *Service) limited(ip string) bool {
	defer telemetry.Step("push.Service.limited")()
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now.Add(-10 * time.Minute)
	var kept []time.Time
	for _, at := range s.hits[ip] {
		if at.After(cut) {
			kept = append(kept, at)
		}
	}
	if len(kept) >= 20 {
		s.hits[ip] = kept
		return true
	}
	s.hits[ip] = append(kept, now)
	return false
}

func hashCredential(raw string) string {
	defer telemetry.Step("push.hashCredential")()
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func contains(list []string, want string) bool {
	defer telemetry.Step("push.contains")()
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func canonicalKey(raw map[string]any, dpop *service.DPoPService) (*ecdsa.PublicKey, string, string, error) {
	defer telemetry.Step("push.canonicalKey")()
	pub, err := publicFromMap(raw)
	if err != nil {
		return nil, "", "", err
	}
	jkt, err := dpop.GetPublicKeyThumbprint(pub)
	if err != nil {
		return nil, "", "", err
	}
	text, err := json.Marshal(dpop.ExportPublicKeyAsJWK(pub))
	if err != nil {
		return nil, "", "", err
	}
	return pub, jkt, string(text), nil
}

func publicFromJWKText(text string) (*ecdsa.PublicKey, error) {
	defer telemetry.Step("push.publicFromJWKText")()
	var raw map[string]any
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, err
	}
	return publicFromMap(raw)
}

func publicFromMap(raw map[string]any) (*ecdsa.PublicKey, error) {
	defer telemetry.Step("push.publicFromMap")()
	if raw["kty"] != "EC" || raw["crv"] != "P-256" {
		return nil, fmt.Errorf("not p-256")
	}
	xText, _ := raw["x"].(string)
	yText, _ := raw["y"].(string)
	x, err := base64.RawURLEncoding.DecodeString(xText)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(yText)
	if err != nil {
		return nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, fmt.Errorf("bad coordinates")
	}
	point := make([]byte, 65)
	point[0] = 4
	copy(point[1:33], x)
	copy(point[33:], y)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

func requestURI(r *http.Request) string {
	defer telemetry.Step("push.requestURI")()
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

func clientIP(r *http.Request) string {
	defer telemetry.Step("push.clientIP")()
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func cryptoRand(buf []byte) (int, error) {
	defer telemetry.Step("push.cryptoRand")()
	return rand.Read(buf)
}
