package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	"github.com/bravo68web/atrium/internal/cache"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

type Handler struct {
	db          *database.DB
	cfg         *config.Config
	keySet      *KeySet
	clients     *repository.ClientRepository
	users       *repository.UserRepository
	tokens      *repository.TokenRepository
	orgs        *repository.OrgRepository
	checkDPoP   func(ctx context.Context, header, method, uri, accessToken string) (string, error)
	fetchSector func(ctx context.Context, rawURL string) ([]byte, error)
	sectorCache cache.Cache
}

func (h *Handler) SetDPoPCheck(fn func(ctx context.Context, header, method, uri, accessToken string) (string, error)) {
	defer telemetry.Step("oidc.Handler.SetDPoPCheck")()
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
	defer telemetry.Step("oidc.NewHandler")()
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

func (h *Handler) orgRole(orgID, userID string) string {
	defer telemetry.Step("oidc.Handler.orgRole")()
	if h == nil || h.orgs == nil || orgID == "" || userID == "" {
		return ""
	}
	role, err := h.orgs.MemberRole(orgID, userID)
	if err != nil {
		return ""
	}
	return role
}

func (h *Handler) OrgRole(orgID, userID string) string {
	defer telemetry.Step("oidc.Handler.OrgRole")()
	return h.orgRole(orgID, userID)
}

// TokenHash is the OIDC at_hash and c_hash value: the left half of SHA-256, base64url.
func TokenHash(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func generateKid() string {
	defer telemetry.Step("oidc.generateKid")()
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
	CHash             string `json:"c_hash,omitempty"`
	Azp               string `json:"azp,omitempty"`
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
	OrgRole           string `json:"org_role,omitempty"`
}

type IDTokenExtra struct {
	SID         string
	AuthTime    time.Time
	OrgID       string
	OrgSlug     string
	AccessToken string
	Code        string
}

func (h *Handler) CreateIDToken(ctx context.Context, clientID, userID, nonce string, scopes []string, extra ...IDTokenExtra) (string, error) {
	defer telemetry.Step("oidc.Handler.CreateIDToken")()
	claims, err := h.identityClaims(ctx, clientID, userID, nonce, scopes, extra...)
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

func (h *Handler) CreateIDTokenWithES256(ctx context.Context, clientID, userID, nonce string, scopes []string, extra ...IDTokenExtra) (string, error) {
	defer telemetry.Step("oidc.Handler.CreateIDTokenWithES256")()
	claims, err := h.identityClaims(ctx, clientID, userID, nonce, scopes, extra...)
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
func (h *Handler) CreateAccessTokenJWT(ctx context.Context, clientID, userID, scope, _ string, lifetime time.Duration, orgID, orgSlug, resource, actor string) (string, error) {
	defer telemetry.Step("oidc.Handler.CreateAccessTokenJWT")()
	if h == nil || h.keySet == nil {
		return "", fmt.Errorf("signing keys are not loaded")
	}
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	sub, err := h.SubjectFor(ctx, clientID, userID)
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
	if role := h.orgRole(orgID, userID); role != "" {
		claims["org_role"] = role
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
	defer telemetry.Step("oidc.Handler.AccessTokenSubject")()
	claims, err := h.parseAccessToken(raw)
	if err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("invalid access token")
	}
	return sub, nil
}

// AccessTokenJTI verifies an access token this server signed and returns jti.
func (h *Handler) AccessTokenJTI(raw string) (string, error) {
	defer telemetry.Step("oidc.Handler.AccessTokenJTI")()
	claims, err := h.parseAccessToken(raw)
	if err != nil {
		return "", err
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return "", fmt.Errorf("invalid access token")
	}
	return jti, nil
}

func (h *Handler) parseAccessToken(raw string) (jwt.MapClaims, error) {
	if h == nil || h.keySet == nil {
		return nil, fmt.Errorf("signing keys are not loaded")
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
		return nil, fmt.Errorf("invalid access token")
	}
	iss, _ := claims["iss"].(string)
	if iss != h.issuer() {
		return nil, fmt.Errorf("invalid access token")
	}
	return claims, nil
}

// SetDataKey decrypts client secrets read by this handler.
func (h *Handler) SetDataKey(key []byte) {
	if h != nil && h.clients != nil {
		h.clients.SetKey(key)
	}
}

// UseTokenVerifier makes JWT access-token lookups on this handler verify the signature.
func (h *Handler) UseTokenVerifier() {
	if h != nil && h.tokens != nil {
		h.tokens.SetAccessVerifier(h.AccessTokenJTI)
	}
}

func signIDToken(method jwt.SigningMethod, kid string, key any, claims jwt.Claims) (string, error) {
	defer telemetry.Step("oidc.signIDToken")()
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func (h *Handler) identityClaims(ctx context.Context, clientID, userID, nonce string, scopes []string, extra ...IDTokenExtra) (jwt.Claims, error) {
	defer telemetry.Step("oidc.Handler.identityClaims")()
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
	sub, err := h.SubjectFor(ctx, clientID, userID)
	if err != nil {
		return nil, err
	}
	if len(mappings) > 0 {
		claims := jwt.MapClaims{
			"iss": h.issuer(),
			"sub": sub,
			"aud": clientID,
			"azp": clientID,
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
		if role := h.orgRole(ex.OrgID, userID); role != "" {
			claims["org_role"] = role
		}
		if hash := TokenHash(ex.AccessToken); hash != "" {
			claims["at_hash"] = hash
		}
		if hash := TokenHash(ex.Code); hash != "" {
			claims["c_hash"] = hash
		}
		for key, value := range applyClaimMappings(mappings, sub, user, scopes) {
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
		OrgRole: h.orgRole(ex.OrgID, userID),
		AtHash:  TokenHash(ex.AccessToken),
		CHash:   TokenHash(ex.Code),
		Azp:     clientID,
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
	defer telemetry.Step("oidc.Handler.HandleJWKS")()
	jwks := h.keySet.ToJWKS()
	if h != nil && h.clients != nil {
		extra, err := h.clients.PublishedClientSigningKeys(time.Now())
		if err != nil {
			http.Error(w, "jwks", http.StatusInternalServerError)
			return
		}
		seen := map[string]bool{}
		for _, key := range jwks.Keys {
			seen[key.Kid] = true
		}
		for _, row := range extra {
			var jwk JWK
			if json.Unmarshal([]byte(row.PublicJWK), &jwk) != nil || jwk.Kid == "" || seen[jwk.Kid] {
				continue
			}
			seen[jwk.Kid] = true
			jwks.Keys = append(jwks.Keys, jwk)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oidc.Handler.HandleUserInfo")()
	scheme, tokenString := splitAuth(r.Header.Get("Authorization"))
	fromQuery := false
	if tokenString == "" {
		tokenString = r.URL.Query().Get("access_token")
		fromQuery = tokenString != ""
		if fromQuery && r.Header.Get("DPoP") != "" {
			scheme = "DPoP"
		} else if fromQuery {
			scheme = "Bearer"
		}
	}
	if tokenString == "" {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Authorization header required")
		return
	}
	if fromQuery {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
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

	dpopOK := h.userInfoDPoP(w, r, at, scheme)
	if !dpopOK {
		return
	}
	// A valid DPoP proof already constrains the sender. The certificate
	// is required only when the token is not presented with that proof.
	if at.CertThumbprint != "" && !strings.EqualFold(scheme, "DPoP") {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "client certificate required")
			return
		}
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		if base64.RawURLEncoding.EncodeToString(sum[:]) != at.CertThumbprint {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "client certificate mismatch")
			return
		}
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

	sub, err := h.SubjectFor(r.Context(), at.ClientID, user.ID)
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
			if role := h.orgRole(at.OrgID, user.ID); role != "" {
				response["org_role"] = role
			}
		}
	}
	mappings := []config.ClaimMapping{}
	if h.cfg != nil {
		mappings = h.cfg.OIDC.ClaimMappings
	}
	if len(mappings) > 0 {
		for key, value := range applyClaimMappings(mappings, sub, user, at.Scopes) {
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
	defer telemetry.Step("oidc.splitAuth")()
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}

func (h *Handler) userInfoDPoP(w http.ResponseWriter, r *http.Request, at *models.AccessToken, scheme string) bool {
	defer telemetry.Step("oidc.Handler.userInfoDPoP")()
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
		jkt, err := h.checkDPoP(r.Context(), r.Header.Get("DPoP"), r.Method, uri, at.Token)
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
	defer telemetry.Step("oidc.Handler.HandleDiscovery")()
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
		"request_object_signing_alg_values_supported":      []string{"RS256", "ES256"},
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
	defer telemetry.Step("oidc.Handler.HandleASMetadata")()
	h.HandleDiscovery(w, r)
}

func discoveryGrants(cfg *config.Config) []string {
	defer telemetry.Step("oidc.discoveryGrants")()
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
	defer telemetry.Step("oidc.Handler.SignRSA")()
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
	defer telemetry.Step("oidc.Handler.issuer")()
	if h.cfg.Security.Issuer != "" {
		return h.cfg.Security.Issuer
	}
	return fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
}

func (h *Handler) CreateLogoutToken(clientID, sub, sid string) (string, error) {
	defer telemetry.Step("oidc.Handler.CreateLogoutToken")()
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
	defer telemetry.Step("oidc.Handler.ParseSignedToken")()
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
	defer telemetry.Step("oidc.writeOIDCError")()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, code, description))
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func (h *Handler) GetKeySet() *KeySet {
	defer telemetry.Step("oidc.Handler.GetKeySet")()
	return h.keySet
}
