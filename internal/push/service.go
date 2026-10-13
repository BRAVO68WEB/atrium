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

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	qrcode "github.com/skip2/go-qrcode"
)

const problemBase = "https://oauth-impl.local/problems/"

// Problem is an RFC 9457 body for the push endpoints.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func (p Problem) Error() string { return p.Detail }

func problem(status int, slug, detail string) Problem {
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
	return strings.TrimRight(s.cfg.Security.Issuer, "/")
}

func (s *Service) Discovery() map[string]any {
	base := s.issuer()
	return map[string]any{
		"registration_endpoint":        base + "/push/register",
		"delivery_modes_supported":     []string{"poll"},
		"interaction_type_supported":   []string{"boolean", "number_choose", "input_manual"},
		"minimum_interaction_type":     s.cfg.Push.MinimumInteractionType,
		"registration_token_ttl":       s.cfg.Push.RegistrationTokenTTL,
		"signing_alg_values_supported": []string{"ES256"},
		"fallback_order":               []string{"poll"},
		"client_attestation_required":  s.cfg.Push.ClientAttestation,
		"revocation_endpoint":          base + "/push/revoke",
		"key_rotation_endpoint":        base + "/push/rotate-key",
		"device_management_endpoint":   base + "/push/devices",
		"max_devices_per_user":         s.cfg.Push.MaxDevicesPerUser,
		"push_wait_timeout_seconds":    10,
		"error_response_format":        "application/problem+json",
	}
}

// Enrollment is what the browser page shows. The token sits in the URL fragment.
type Enrollment struct {
	Token string
	URL   string
	QR    string
}

func (s *Service) IssueEnrollment(userID, clientID string, sign func(claims jwt.MapClaims) (string, error)) (Enrollment, error) {
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
}

type Registered struct {
	DeviceID   string `json:"device_id"`
	Credential string `json:"device_credential"`
	Ref        string `json:"registration_ref"`
	ExpiresIn  int    `json:"expires_in"`
}

func (s *Service) Register(ip string, body []byte, keyfunc jwt.Keyfunc) (Registered, error) {
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
	pub, jkt, jwkText, err := canonicalKey(req.PublicKey, s.dpop)
	if err != nil || pub == nil {
		return Registered{}, problem(http.StatusBadRequest, "invalid_public_key", "public key must be P-256")
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM push_devices WHERE user_id = ? AND status = 'active'`, userID).Scan(&n); err != nil {
		return Registered{}, err
	}
	if n >= s.cfg.Push.MaxDevicesPerUser {
		return Registered{}, problem(http.StatusForbidden, "device_limit", "device limit reached")
	}
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
	return Registered{DeviceID: id, Credential: credential, Ref: "urn:push-reg:" + id, ExpiresIn: s.cfg.Push.RegistrationTokenTTL}, nil
}

// Device is a row safe to show the signed-in user.
type Device struct {
	ID               string   `json:"device_id"`
	Platform         string   `json:"platform"`
	CreatedAt        string   `json:"created_at"`
	LastUsedAt       string   `json:"last_used_at,omitempty"`
	InteractionTypes []string `json:"interaction_types"`
	Status           string   `json:"status"`
}

func (s *Service) List(userID string) ([]Device, error) {
	rows, err := s.db.Query(`SELECT id, COALESCE(platform, ''), created_at, COALESCE(last_used_at, ''), interaction_types, status FROM push_devices WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		var item Device
		var raw string
		if err := rows.Scan(&item.ID, &item.Platform, &item.CreatedAt, &item.LastUsedAt, &raw, &item.Status); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &item.InteractionTypes)
		out = append(out, item)
	}
	if out == nil {
		out = []Device{}
	}
	return out, rows.Err()
}

type deviceRow struct {
	id     string
	userID string
	jwk    string
	jkt    string
	hash   string
	status string
}

func (s *Service) authenticate(r *http.Request, deviceID, credential string) (deviceRow, error) {
	var row deviceRow
	err := s.db.QueryRow(`SELECT id, user_id, jwk, jkt, credential_hash, status FROM push_devices WHERE id = ?`, deviceID).Scan(&row.id, &row.userID, &row.jwk, &row.jkt, &row.hash, &row.status)
	if err != nil || row.status != "active" || subtle.ConstantTimeCompare([]byte(row.hash), []byte(hashCredential(credential))) != 1 {
		return deviceRow{}, problem(http.StatusUnauthorized, "invalid_device_credential", "device credential is not valid")
	}
	if err := s.checkNonce(r, deviceID); err != nil {
		return deviceRow{}, err
	}
	if s.dpop == nil || r.Header.Get("DPoP") == "" {
		return deviceRow{}, problem(http.StatusUnauthorized, "dpop_required", "DPoP proof is required")
	}
	proof, err := s.dpop.ValidateDPoPProof(r.Header.Get("DPoP"), r.Method, requestURI(r), "")
	if err != nil || proof.JKT != row.jkt {
		return deviceRow{}, problem(http.StatusUnauthorized, "dpop_required", "DPoP proof does not match the device key")
	}
	return row, nil
}

func (s *Service) Revoke(r *http.Request, deviceID, credential string) (string, error) {
	if _, err := s.authenticate(r, deviceID, credential); err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`UPDATE push_devices SET status = 'revoked', credential_hash = '', last_used_at = ? WHERE id = ?`, s.now().UTC().Format(time.RFC3339), deviceID); err != nil {
		return "", err
	}
	s.cascadeRevoke(deviceID)
	return s.issueNonce(deviceID), nil
}

type rotateRequest struct {
	DeviceID     string         `json:"device_id"`
	NewPublicKey map[string]any `json:"new_public_key"`
	Proof        string         `json:"proof_of_possession"`
}

func (s *Service) Rotate(r *http.Request, body []byte, credential string) (Registered, string, error) {
	var req rotateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return Registered{}, "", problem(http.StatusBadRequest, "invalid_public_key", "rotation body is invalid")
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
	if _, err := s.db.Exec(`UPDATE push_devices SET jwk = ?, jkt = ?, credential_hash = ?, last_used_at = ? WHERE id = ?`,
		newText, newJKT, hashCredential(credentialNew), s.now().UTC().Format(time.RFC3339), row.id); err != nil {
		return Registered{}, "", err
	}
	return Registered{DeviceID: row.id, Credential: credentialNew, Ref: "urn:push-reg:" + row.id, ExpiresIn: s.cfg.Push.RegistrationTokenTTL}, s.issueNonce(row.id), nil
}

func (s *Service) checkNonce(r *http.Request, deviceID string) error {
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
	buf := make([]byte, 16)
	_, _ = cryptoRand(buf)
	value := base64.RawURLEncoding.EncodeToString(buf)
	s.mu.Lock()
	s.nonce[deviceID] = nonceState{value: value}
	s.mu.Unlock()
	return value
}

func (s *Service) limited(ip string) bool {
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
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func canonicalKey(raw map[string]any, dpop *service.DPoPService) (*ecdsa.PublicKey, string, string, error) {
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
	var raw map[string]any
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, err
	}
	return publicFromMap(raw)
}

func publicFromMap(raw map[string]any) (*ecdsa.PublicKey, error) {
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
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func cryptoRand(buf []byte) (int, error) {
	return rand.Read(buf)
}
