package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/oauth-impl/internal/cache"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

type Handler struct {
	db          *database.DB
	cfg         *config.Config
	keySet      *KeySet
	clients     *repository.ClientRepository
	users       *repository.UserRepository
	tokens      *repository.TokenRepository
	orgs        *repository.OrgRepository
	checkDPoP   func(header, method, uri, accessToken string) (string, error)
	fetchSector func(ctx context.Context, rawURL string) ([]byte, error)
	sectorCache cache.Cache
}

func (h *Handler) SetDPoPCheck(fn func(header, method, uri, accessToken string) (string, error)) {
	if h != nil {
		h.checkDPoP = fn
	}
}

type KeySet struct {
	mu   sync.RWMutex
	db   database.SQL
	keys []storedKey
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewHandler(db *database.DB, cfg *config.Config) (*Handler, error) {
	var handle database.SQL
	if db != nil {
		handle = db
	}
	keySet, err := LoadKeySet(handle)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key set: %w", err)
	}

	h := &Handler{
		db:     db,
		cfg:    cfg,
		keySet: keySet,
	}
	if db != nil {
		h.clients = repository.NewClientRepository(db)
		h.users = repository.NewUserRepository(db)
		h.tokens = repository.NewTokenRepository(db)
		h.orgs = repository.NewOrgRepository(db)
	}
	return h, nil
}

func generateKid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce             string `json:"nonce,omitempty"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	AtHash            string `json:"at_hash,omitempty"`
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	SID               string `json:"sid,omitempty"`
	Sub               string `json:"sub"`
	OrgID             string `json:"org_id,omitempty"`
	OrgSlug           string `json:"org_slug,omitempty"`
}

type IDTokenExtra struct {
	SID      string
	AuthTime time.Time
	OrgID    string
	OrgSlug  string
}

func (h *Handler) CreateIDToken(clientID, userID, nonce string, scopes []string, extra ...IDTokenExtra) (string, error) {
	claims, err := h.identityClaims(clientID, userID, nonce, scopes, extra...)
	if err != nil {
		return "", err
	}
	key, kid := h.keySet.GetRSAKey()
	signed, err := signIDToken(jwt.SigningMethodRS256, kid, key, claims)
	if err != nil {
		return "", err
	}
	return h.sealIDToken(clientID, signed)
}

func (h *Handler) CreateIDTokenWithES256(clientID, userID, nonce string, scopes []string, extra ...IDTokenExtra) (string, error) {
	claims, err := h.identityClaims(clientID, userID, nonce, scopes, extra...)
	if err != nil {
		return "", err
	}
	key, kid := h.keySet.GetECKey()
	signed, err := signIDToken(jwt.SigningMethodES256, kid, key, claims)
	if err != nil {
		return "", err
	}
	return h.sealIDToken(clientID, signed)
}

// CreateAccessTokenJWT signs an access token with the active RSA key.
// The profile is RFC 9068: typ at+jwt, aud is the resource or the issuer,
// and client_id plus azp name the client. Callers still store the compact
// token so revocation and UserInfo keep working.
func (h *Handler) CreateAccessTokenJWT(clientID, userID, scope, _ string, lifetime time.Duration, orgID, orgSlug, resource, actor string) (string, error) {
	if h == nil || h.keySet == nil {
		return "", fmt.Errorf("signing keys are not loaded")
	}
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	sub, err := h.SubjectFor(clientID, userID)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	now := time.Now()
	audience := h.issuer()
	if strings.TrimSpace(resource) != "" {
		audience = resource
	}
	claims := jwt.MapClaims{
		"iss":       h.issuer(),
		"sub":       sub,
		"aud":       audience,
		"exp":       now.Add(lifetime).Unix(),
		"iat":       now.Unix(),
		"jti":       hex.EncodeToString(raw),
		"client_id": clientID,
		"azp":       clientID,
		"scope":     scope,
	}
	if orgID != "" {
		claims["org_id"] = orgID
	}
	if orgSlug != "" {
		claims["org_slug"] = orgSlug
	}
	if actor != "" {
		claims["act"] = map[string]string{"sub": actor}
	}
	key, kid := h.keySet.GetRSAKey()
	if key == nil {
		return "", fmt.Errorf("no active rsa signing key")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "at+jwt"
	return token.SignedString(key)
}

// AccessTokenSubject verifies an access token this server signed and returns sub.
func (h *Handler) AccessTokenSubject(raw string) (string, error) {
	if h == nil || h.keySet == nil {
		return "", fmt.Errorf("signing keys are not loaded")
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		if key, ok := h.keySet.publicByKid(kid); ok {
			return key, nil
		}
		return nil, fmt.Errorf("unknown signing key")
	})
	if err != nil || token == nil || !token.Valid {
		return "", fmt.Errorf("invalid access token")
	}
	iss, _ := claims["iss"].(string)
	if iss != h.issuer() {
		return "", fmt.Errorf("invalid access token")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("invalid access token")
	}
	return sub, nil
}

func signIDToken(method jwt.SigningMethod, kid string, key any, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func (h *Handler) identityClaims(clientID, userID, nonce string, scopes []string, extra ...IDTokenExtra) (jwt.Claims, error) {
	var ex IDTokenExtra
	if len(extra) > 0 {
		ex = extra[0]
	}
	now := time.Now()
	var user *models.User
	if h.users != nil {
		user, _ = h.users.GetByID(userID)
	}
	mappings := []config.ClaimMapping{}
	if h.cfg != nil {
		mappings = h.cfg.OIDC.ClaimMappings
	}
	sub, err := h.SubjectFor(clientID, userID)
	if err != nil {
		return nil, err
	}
	if len(mappings) > 0 {
		claims := jwt.MapClaims{
			"iss": h.issuer(),
			"sub": sub,
			"aud": clientID,
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		}
		if nonce != "" {
			claims["nonce"] = nonce
		}
		if ex.SID != "" {
			claims["sid"] = ex.SID
		}
		if !ex.AuthTime.IsZero() {
			claims["auth_time"] = ex.AuthTime.Unix()
		}
		if ex.OrgID != "" {
			claims["org_id"] = ex.OrgID
		}
		if ex.OrgSlug != "" {
			claims["org_slug"] = ex.OrgSlug
		}
		for key, value := range applyClaimMappings(mappings, user, scopes) {
			claims[key] = value
		}
		return claims, nil
	}

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.issuer(),
			Subject:   sub,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Sub:     sub,
		Nonce:   nonce,
		SID:     ex.SID,
		OrgID:   ex.OrgID,
		OrgSlug: ex.OrgSlug,
	}
	if !ex.AuthTime.IsZero() {
		claims.AuthTime = ex.AuthTime.Unix()
	}
	if user != nil {
		for _, scope := range scopes {
			switch scope {
			case "profile":
				claims.Name = user.Username
				claims.PreferredUsername = user.Username
				claims.GivenName = user.GivenName
				claims.FamilyName = user.FamilyName
			case "email":
				claims.Email = user.Email
				claims.EmailVerified = user.EmailVerified
			}
		}
	}
	return claims, nil
}

func (h *Handler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.keySet.ToJWKS()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=3600")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	scheme, tokenString := splitAuth(r.Header.Get("Authorization"))
	if tokenString == "" {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Authorization header required")
		return
	}

	if h.tokens == nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Token not found")
		return
	}
	at, err := h.tokens.GetAccessToken(tokenString)
	if err != nil {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Token not found")
		return
	}

	if at.Revoked || time.Now().After(at.ExpiresAt) {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Token expired or revoked")
		return
	}

	if !h.userInfoDPoP(w, r, at, scheme) {
		return
	}

	if h.users == nil {
		writeOIDCError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	user, err := h.users.GetByID(at.UserID)
	if err != nil {
		writeOIDCError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	sub, err := h.SubjectFor(at.ClientID, user.ID)
	if err != nil {
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "Failed to resolve subject")
		return
	}
	response := map[string]interface{}{
		"sub": sub,
	}
	if at.OrgID != "" {
		response["org_id"] = at.OrgID
		if h.orgs != nil {
			if org, err := h.orgs.Get(at.OrgID); err == nil && org != nil && org.Slug != "" {
				response["org_slug"] = org.Slug
			}
		}
	}
	mappings := []config.ClaimMapping{}
	if h.cfg != nil {
		mappings = h.cfg.OIDC.ClaimMappings
	}
	if len(mappings) > 0 {
		for key, value := range applyClaimMappings(mappings, user, at.Scopes) {
			response[key] = value
		}
	} else {
		for _, scope := range at.Scopes {
			switch scope {
			case "profile":
				response["name"] = user.Username
				response["preferred_username"] = user.Username
				response["given_name"] = user.GivenName
				response["family_name"] = user.FamilyName
				response["picture"] = ""
				response["locale"] = "en"
				response["updated_at"] = user.CreatedAt.Unix()
			case "email":
				response["email"] = user.Email
				response["email_verified"] = user.EmailVerified
			case "phone":
				response["phone_number"] = user.PhoneNumber
				response["phone_number_verified"] = user.PhoneNumber != ""
			}
		}
	}

	sealed, encrypted, err := h.sealUserInfo(at.ClientID, response)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_client", "Failed to encrypt UserInfo")
		return
	}
	if encrypted {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = io.WriteString(w, sealed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func splitAuth(header string) (string, string) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}

func (h *Handler) userInfoDPoP(w http.ResponseWriter, r *http.Request, at *models.AccessToken, scheme string) bool {
	bound := at.TokenType == "DPoP" || at.DPoPJKT != ""
	if h.clients != nil {
		if client, err := h.clients.GetByID(at.ClientID); err == nil && client.DPoPBoundAccessTokens {
			bound = true
		}
	}
	if bound {
		if !strings.EqualFold(scheme, "DPoP") {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "DPoP proof required")
			return false
		}
		if h.checkDPoP == nil {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "DPoP proof required")
			return false
		}
		proofScheme := "http"
		if r.TLS != nil {
			proofScheme = "https"
		}
		uri := fmt.Sprintf("%s://%s%s", proofScheme, r.Host, r.URL.Path)
		jkt, err := h.checkDPoP(r.Header.Get("DPoP"), r.Method, uri, at.Token)
		if err != nil {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return false
		}
		if at.DPoPJKT != "" && jkt != at.DPoPJKT {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "DPoP key does not match the token")
			return false
		}
		return true
	}
	if !strings.EqualFold(scheme, "Bearer") {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Bearer token required")
		return false
	}
	return true
}

func (h *Handler) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
	}

	discovery := map[string]interface{}{
		"issuer":                                           issuer,
		"authorization_endpoint":                           issuer + "/oauth/authorize",
		"token_endpoint":                                   issuer + "/oauth/token",
		"userinfo_endpoint":                                issuer + "/oidc/userinfo",
		"jwks_uri":                                         issuer + "/oidc/jwks",
		"registration_endpoint":                            issuer + "/oauth/register",
		"revocation_endpoint":                              issuer + "/oauth/revoke",
		"introspection_endpoint":                           issuer + "/oauth/introspect",
		"device_authorization_endpoint":                    issuer + "/oauth/device",
		"pushed_authorization_request_endpoint":            issuer + "/oauth/par",
		"backchannel_authentication_endpoint":              issuer + "/oauth/bc-authorize",
		"scopes_supported":                                 h.cfg.OIDC.SupportedScopes,
		"response_types_supported":                         []string{"code", "token", "id_token", "code id_token", "code token", "code id_token token", "none"},
		"response_modes_supported":                         []string{"query", "fragment", "form_post"},
		"grant_types_supported":                            discoveryGrants(h.cfg),
		"token_endpoint_auth_methods_supported":            h.cfg.OIDC.SupportedAuthMethods,
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "ES256"},
		"subject_types_supported":                          []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported":            []string{"RS256", "ES256"},
		"id_token_encryption_alg_values_supported":         []string{encAlgRSAOAEP256},
		"id_token_encryption_enc_values_supported":         []string{encA256GCM},
		"userinfo_encryption_alg_values_supported":         []string{encAlgRSAOAEP256},
		"userinfo_encryption_enc_values_supported":         []string{encA256GCM},
		"code_challenge_methods_supported":                 []string{"S256", "plain"},
		"claims_supported":                                 h.cfg.OIDC.SupportedClaims,
		"claims_parameter_supported":                       true,
		"request_parameter_supported":                      true,
		"request_uri_parameter_supported":                  true,
		"request_object_signing_alg_values_supported":      []string{"RS256", "ES256", "none"},
		"require_pushed_authorization_requests":            false,
		"backchannel_token_delivery_modes_supported":       []string{"poll"},
		"backchannel_user_code_parameter_supported":        false,
		"tls_client_certificate_bound_access_tokens":       h.cfg.Security.MTLS.CertBinding,
		"dpop_signing_alg_values_supported":                []string{"ES256", "RS256"},
		"authorization_response_iss_parameter_supported":   true,
		"end_session_endpoint":                             issuer + "/oauth/logout",
		"backchannel_logout_supported":                     true,
		"backchannel_logout_session_supported":             true,
	}

	if h.cfg.XAA.Enabled {
		discovery["authorization_grant_profiles_supported"] = []string{config.XAAIDJAGProfile}
	}

	// Add mTLS endpoint aliases if mTLS is enabled
	if h.cfg.Security.MTLS.Enabled && h.cfg.Server.TLS.Enabled {
		mtlsIssuer := fmt.Sprintf("https://localhost:%d", h.cfg.Server.Port)
		discovery["mtls_endpoint_aliases"] = map[string]string{
			"token_endpoint":         mtlsIssuer + "/oauth/token",
			"revocation_endpoint":    mtlsIssuer + "/oauth/revoke",
			"introspection_endpoint": mtlsIssuer + "/oauth/introspect",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(discovery)
}

func (h *Handler) HandleASMetadata(w http.ResponseWriter, r *http.Request) {
	h.HandleDiscovery(w, r)
}

func discoveryGrants(cfg *config.Config) []string {
	var src []string
	enabled := false
	if cfg != nil {
		src = cfg.OIDC.SupportedGrantTypes
		enabled = cfg.XAA.Enabled
	}
	out := make([]string, 0, len(src)+1)
	for _, grant := range src {
		if grant == config.XAAJWTBearerGrant {
			continue
		}
		out = append(out, grant)
	}
	if enabled {
		out = append(out, config.XAAJWTBearerGrant)
	}
	return out
}

// SignRSA signs claims with the active RSA key. typ is the JOSE header type.
func (h *Handler) SignRSA(claims jwt.MapClaims, typ string) (string, error) {
	if h == nil || h.keySet == nil {
		return "", fmt.Errorf("signing keys are not loaded")
	}
	key, kid := h.keySet.GetRSAKey()
	if key == nil {
		return "", fmt.Errorf("no active rsa signing key")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	if typ != "" {
		token.Header["typ"] = typ
	}
	return token.SignedString(key)
}

func (h *Handler) issuer() string {
	if h.cfg.Security.Issuer != "" {
		return h.cfg.Security.Issuer
	}
	return fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
}

func (h *Handler) CreateLogoutToken(clientID, sub, sid string) (string, error) {
	now := time.Now()
	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"iss": h.issuer(),
		"aud": clientID,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"jti": hex.EncodeToString(jtiRaw),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if sub != "" {
		claims["sub"] = sub
	}
	if sid != "" {
		claims["sid"] = sid
	}
	key, kid := h.keySet.GetRSAKey()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func (h *Handler) ParseSignedToken(token string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if pub, ok := h.keySet.publicByKid(kid); ok {
			return pub, nil
		}
		switch t.Method.Alg() {
		case jwt.SigningMethodRS256.Alg():
			key, _ := h.keySet.GetRSAKey()
			if key == nil {
				return nil, fmt.Errorf("no rsa key")
			}
			return &key.PublicKey, nil
		case jwt.SigningMethodES256.Alg():
			key, _ := h.keySet.GetECKey()
			if key == nil {
				return nil, fmt.Errorf("no ec key")
			}
			return &key.PublicKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method")
		}
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func writeOIDCError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, code, description))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func (h *Handler) GetKeySet() *KeySet {
	return h.keySet
}
