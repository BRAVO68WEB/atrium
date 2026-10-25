package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/atrium/internal/cache"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

const idJAGLifetime = 5 * time.Minute

// GrantFailure is an OAuth token error. Code is the error parameter.
type GrantFailure struct {
	Status      int
	Code        string
	Description string
}

func (e *GrantFailure) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

func fail(status int, code, description string) error {
	defer telemetry.Step("service.fail")()
	return &GrantFailure{Status: status, Code: code, Description: description}
}

// RedeemedGrant is the local user and scopes an ID-JAG authorizes.
type RedeemedGrant struct {
	UserID string
	Scopes []string
}

// XAA issues and checks Identity Assertion JWT authorization grants.
type XAA struct {
	cfg   *config.Config
	users *repository.UserRepository
	store cache.Cache
	now   func() time.Time
	fetch func(ctx context.Context, rawURL string) ([]byte, int, error)
}

func NewXAA(cfg *config.Config, users *repository.UserRepository, store cache.Cache) *XAA {
	defer telemetry.Step("service.NewXAA")()
	return &XAA{
		cfg:   cfg,
		users: users,
		store: store,
		now:   time.Now,
		fetch: func(ctx context.Context, rawURL string) ([]byte, int, error) {
			return FetchSafe(ctx, cfg, "GET", rawURL, nil, nil)
		},
	}
}

// Issue verifies raw, signs an ID-JAG, then records that raw was used.
// verify and sign are the server's ID-token parser and RSA signer.
func (s *XAA) Issue(ctx context.Context, clientID, raw, audience, scope string, verify func(string) (jwt.MapClaims, error), sign func(jwt.MapClaims, string) (string, error)) (string, string, int, error) {
	defer telemetry.Step("service.XAA.Issue")()
	if s == nil || s.cfg == nil || !s.cfg.XAA.Enabled {
		return "", "", 0, fail(400, "invalid_request", "Cross-app access is disabled")
	}
	if strings.TrimSpace(raw) == "" || verify == nil {
		return "", "", 0, fail(400, "invalid_grant", "Invalid subject token")
	}
	if sign == nil {
		return "", "", 0, fail(500, "server_error", "Failed to sign the assertion")
	}
	if jwtTyp(raw) == config.XAAIDJAGTyp {
		return "", "", 0, fail(400, "invalid_grant", "Subject token is not an ID token")
	}
	claims, err := verify(raw)
	if err != nil || claims == nil {
		return "", "", 0, fail(400, "invalid_grant", "Invalid subject token")
	}
	if !sameIssuer(claimString(claims, "iss"), s.issuer()) {
		return "", "", 0, fail(400, "invalid_grant", "ID token issuer is not this server")
	}
	if !audMatch(claims, clientID, func(have, want string) bool { return have == want }) {
		return "", "", 0, fail(400, "invalid_grant", "ID token audience does not include this client")
	}
	if azp := claimString(claims, "azp"); azp != "" && azp != clientID {
		return "", "", 0, fail(400, "invalid_grant", "ID token audience does not include this client")
	}
	sub := claimString(claims, "sub")
	if sub == "" {
		return "", "", 0, fail(400, "invalid_grant", "Invalid subject token")
	}
	exp, ok := claimTime(claims["exp"])
	if !ok || !exp.After(s.now()) {
		return "", "", 0, fail(400, "invalid_grant", "Subject token is expired")
	}
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return "", "", 0, fail(400, "invalid_request", "audience is required")
	}
	trust, found := s.trust(clientID, audience)
	if !found {
		return "", "", 0, fail(400, "invalid_target", "Audience is not allowed")
	}
	scopes, err := scopesFromPolicy(scope, trust.Scopes)
	if err != nil {
		return "", "", 0, err
	}
	jti, err := randomID()
	if err != nil {
		return "", "", 0, fail(500, "server_error", "Failed to issue the assertion")
	}
	now := s.now()
	issued := jwt.MapClaims{
		"iss":       s.issuer(),
		"sub":       sub,
		"aud":       trust.Audience,
		"exp":       now.Add(idJAGLifetime).Unix(),
		"iat":       now.Unix(),
		"jti":       jti,
		"client_id": trust.ResourceClientID,
	}
	granted := strings.Join(scopes, " ")
	if granted != "" {
		issued["scope"] = granted
	}
	if email := claimString(claims, "email"); email != "" {
		issued["email"] = email
	}
	compact, err := sign(issued, config.XAAIDJAGTyp)
	if err != nil || compact == "" {
		return "", "", 0, fail(500, "server_error", "Failed to sign the assertion")
	}
	if err := s.consume(ctx, "xaa:subject:"+tokenKey(raw), exp, "Subject token was already used"); err != nil {
		return "", "", 0, err
	}
	return compact, granted, int(idJAGLifetime.Seconds()), nil
}

// Redeem checks an ID-JAG and resolves the verified local user.
func (s *XAA) Redeem(ctx context.Context, clientID, assertion string) (*RedeemedGrant, error) {
	defer telemetry.Step("service.XAA.Redeem")()
	if s == nil || s.cfg == nil || !s.cfg.XAA.Enabled {
		return nil, fail(400, "unsupported_grant_type", "Cross-app access is disabled")
	}
	assertion = strings.TrimSpace(assertion)
	if assertion == "" {
		return nil, fail(400, "invalid_request", "assertion is required")
	}
	if len(assertion) > 16*1024 || strings.Count(assertion, ".") != 2 {
		return nil, fail(400, "invalid_grant", "Assertion is not an ID-JAG")
	}
	header, err := jwtPart(assertion, 0)
	if err != nil || header["alg"] != "RS256" || header["typ"] != config.XAAIDJAGTyp {
		return nil, fail(400, "invalid_grant", "Assertion is not an ID-JAG")
	}
	untrusted, err := jwtPart(assertion, 1)
	if err != nil {
		return nil, fail(400, "invalid_grant", "Assertion is not an ID-JAG")
	}
	issuer := claimString(untrusted, "iss")
	idp, found := s.idp(issuer)
	if !found {
		return nil, fail(400, "invalid_grant", "Issuer is not trusted")
	}
	body, status, err := s.fetch(ctx, idp.JWKSURI)
	if err != nil || status != 200 {
		return nil, fail(400, "invalid_grant", "Issuer keys are unavailable")
	}
	keys, err := parseRSAJWKS(body)
	if err != nil || len(keys) == 0 {
		return nil, fail(400, "invalid_grant", "Issuer keys are unavailable")
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithLeeway(time.Minute))
	token, err := parser.ParseWithClaims(assertion, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub := rsaKey(keys, kid)
		if pub == nil {
			return nil, fmt.Errorf("unknown signing key")
		}
		return pub, nil
	})
	if err != nil || token == nil || !token.Valid {
		return nil, fail(400, "invalid_grant", "Assertion is not valid")
	}
	if typ, _ := token.Header["typ"].(string); typ != config.XAAIDJAGTyp {
		return nil, fail(400, "invalid_grant", "Assertion is not an ID-JAG")
	}
	if !sameIssuer(claimString(claims, "iss"), idp.Issuer) {
		return nil, fail(400, "invalid_grant", "Issuer is not trusted")
	}
	if !audMatch(claims, s.issuer(), sameIssuer) {
		return nil, fail(400, "invalid_grant", "Audience is not this server")
	}
	if claimString(claims, "client_id") != clientID {
		return nil, fail(400, "invalid_grant", "client_id does not match this client")
	}
	if claimString(claims, "sub") == "" {
		return nil, fail(400, "invalid_grant", "Assertion is not valid")
	}
	exp, ok := claimTime(claims["exp"])
	iat, iatOK := claimTime(claims["iat"])
	if !ok || !iatOK || !exp.After(s.now()) || iat.After(s.now().Add(time.Minute)) || !exp.After(iat) {
		return nil, fail(400, "invalid_grant", "Assertion is expired")
	}
	jti := claimString(claims, "jti")
	if jti == "" || len(jti) > 128 {
		return nil, fail(400, "invalid_grant", "Assertion is not valid")
	}
	scopeText, err := scopeText(claims["scope"])
	if err != nil {
		return nil, err
	}
	scopes, err := scopesFromPolicy(scopeText, idp.Scopes)
	if err != nil {
		return nil, err
	}
	email := claimString(claims, "email")
	userID, err := s.localUser(email)
	if err != nil {
		return nil, err
	}
	if err := s.consume(ctx, "xaa:used:"+tokenKey(claimString(claims, "iss")+"\n"+jti), exp, "Assertion was already used"); err != nil {
		return nil, err
	}
	return &RedeemedGrant{UserID: userID, Scopes: scopes}, nil
}

func (s *XAA) localUser(email string) (string, error) {
	defer telemetry.Step("service.XAA.localUser")()
	if email == "" || s.users == nil {
		return "", fail(400, "invalid_grant", "No verified user for that email")
	}
	user, err := s.users.GetByEmail(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fail(400, "invalid_grant", "No verified user for that email")
		}
		return "", fail(500, "server_error", "Failed to resolve the user")
	}
	if user == nil || user.Disabled || !user.EmailVerified || strings.TrimSpace(user.Email) == "" {
		return "", fail(400, "invalid_grant", "No verified user for that email")
	}
	return user.ID, nil
}

func (s *XAA) trust(clientID, audience string) (config.XAATrust, bool) {
	defer telemetry.Step("service.XAA.trust")()
	for _, row := range s.cfg.XAA.Trusts {
		if row.ClientID == clientID && sameIssuer(row.Audience, audience) {
			return row, true
		}
	}
	return config.XAATrust{}, false
}

func (s *XAA) idp(issuer string) (config.XAAIdentityProvider, bool) {
	defer telemetry.Step("service.XAA.idp")()
	for _, row := range s.cfg.XAA.IDPs {
		if sameIssuer(row.Issuer, issuer) {
			return row, true
		}
	}
	return config.XAAIdentityProvider{}, false
}

func (s *XAA) issuer() string {
	defer telemetry.Step("service.XAA.issuer")()
	if s != nil && s.cfg != nil && s.cfg.Security.Issuer != "" {
		return s.cfg.Security.Issuer
	}
	return "http://localhost:8080"
}

func (s *XAA) consume(ctx context.Context, key string, until time.Time, replay string) error {
	defer telemetry.Step("service.XAA.consume")()
	if s.store == nil {
		return fail(500, "server_error", "Replay cache is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ttl := until.Sub(s.now())
	if ttl <= 0 {
		return fail(400, "invalid_grant", "Token is expired")
	}
	ok, err := s.store.Add(ctx, key, []byte("1"), ttl)
	if err != nil {
		return fail(500, "server_error", "Replay cache failed")
	}
	if !ok {
		return fail(400, "invalid_grant", replay)
	}
	return nil
}

func scopesFromPolicy(requested string, allowed []string) ([]string, error) {
	defer telemetry.Step("service.scopesFromPolicy")()
	scopes, err := AllowedScopes(requested, allowed)
	if err != nil || len(scopes) == 0 {
		return nil, fail(400, "invalid_scope", "Scope is not allowed")
	}
	return scopes, nil
}

func sameIssuer(left, right string) bool {
	defer telemetry.Step("service.sameIssuer")()
	return strings.TrimRight(strings.TrimSpace(left), "/") == strings.TrimRight(strings.TrimSpace(right), "/")
}

func claimString(claims jwt.MapClaims, key string) string {
	defer telemetry.Step("service.claimString")()
	if claims == nil {
		return ""
	}
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func claimTime(value any) (time.Time, bool) {
	defer telemetry.Step("service.claimTime")()
	switch n := value.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	case int:
		return time.Unix(int64(n), 0), true
	case json.Number:
		parsed, err := n.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(parsed, 0), true
	default:
		return time.Time{}, false
	}
}

func audMatch(claims jwt.MapClaims, want string, match func(have, want string) bool) bool {
	defer telemetry.Step("service.audMatch")()
	if claims == nil || match == nil {
		return false
	}
	switch value := claims["aud"].(type) {
	case string:
		return match(value, want)
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok && match(text, want) {
				return true
			}
		}
	case []string:
		for _, text := range value {
			if match(text, want) {
				return true
			}
		}
	}
	return false
}

func scopeText(value any) (string, error) {
	defer telemetry.Step("service.scopeText")()
	if value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fail(400, "invalid_grant", "Scope is not a string")
	}
	return text, nil
}

func tokenKey(raw string) string {
	defer telemetry.Step("service.tokenKey")()
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomID() (string, error) {
	defer telemetry.Step("service.randomID")()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func jwtTyp(raw string) string {
	defer telemetry.Step("service.jwtTyp")()
	header, err := jwtPart(raw, 0)
	if err != nil {
		return ""
	}
	typ, _ := header["typ"].(string)
	return typ
}

func jwtPart(raw string, index int) (jwt.MapClaims, error) {
	defer telemetry.Step("service.jwtPart")()
	parts := strings.Split(raw, ".")
	if len(parts) < index+1 {
		return nil, fmt.Errorf("malformed jwt")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

type rsaJWK struct {
	kid string
	key *rsa.PublicKey
}

func parseRSAJWKS(body []byte) ([]rsaJWK, error) {
	defer telemetry.Step("service.parseRSAJWKS")()
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make([]rsaJWK, 0, len(doc.Keys))
	for _, key := range doc.Keys {
		if key.Kty != "RSA" || (key.Use != "" && key.Use != "sig") || (key.Alg != "" && key.Alg != "RS256") {
			continue
		}
		pub, err := rsaPublic(key.N, key.E)
		if err != nil {
			continue
		}
		out = append(out, rsaJWK{kid: key.Kid, key: pub})
	}
	return out, nil
}

func rsaPublic(nText, eText string) (*rsa.PublicKey, error) {
	defer telemetry.Step("service.rsaPublic")()
	nBytes, err := decodeB64(nText)
	if err != nil {
		return nil, err
	}
	eBytes, err := decodeB64(eText)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if n.BitLen() < 2048 || e.BitLen() > 31 || e.Sign() <= 0 {
		return nil, fmt.Errorf("rsa key is not usable")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func rsaKey(keys []rsaJWK, kid string) *rsa.PublicKey {
	defer telemetry.Step("service.rsaKey")()
	if kid != "" {
		for _, key := range keys {
			if key.kid == kid {
				return key.key
			}
		}
		return nil
	}
	if len(keys) == 1 {
		return keys[0].key
	}
	return nil
}

func decodeB64(value string) ([]byte, error) {
	defer telemetry.Step("service.decodeB64")()
	value = strings.TrimSpace(value)
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
