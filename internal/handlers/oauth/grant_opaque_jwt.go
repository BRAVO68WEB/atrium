package oauth

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

const maxCustomClaims = 16
const maxClaimString = 256

// handleOpaqueToJWT exchanges an opaque access token for a JWT.
// The form field claims is a JSON object of extra claims.
func (h *Handler) handleOpaqueToJWT(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.handleOpaqueToJWT")()
	client, ok := h.tokenCaller(w, r)
	if !ok {
		return
	}
	if !service.HasGrant(client.GrantTypes, config.OpaqueToJWTGrant) {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client is not authorized for this grant")
		return
	}
	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	subjectToken := strings.TrimSpace(r.Form.Get("subject_token"))
	if subjectToken == "" {
		subjectToken = strings.TrimSpace(r.Form.Get("token"))
	}
	if subjectToken == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}
	if strings.Count(subjectToken, ".") == 2 {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token must be an opaque access token")
		return
	}
	extra, err := customClaims(r.Form.Get("claims"))
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	subject, err := h.tokenRepo.GetAccessToken(subjectToken)
	if err != nil || subject == nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid subject_token")
		return
	}
	if subject.Revoked || time.Now().After(subject.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token is expired or revoked")
		return
	}
	if subject.ClientID != client.ID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token was not issued to this client")
		return
	}
	scopes, err := service.AllowedScopes(r.Form.Get("scope"), subject.Scopes)
	if err != nil || len(scopes) == 0 {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "Scope is not allowed")
		return
	}
	scopes, err = h.narrowScopes(subject.UserID, subject.OrgID, scopes)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to resolve scopes")
		return
	}
	if len(scopes) == 0 {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "Scope is not allowed")
		return
	}
	lifetime := time.Until(subject.ExpiresAt)
	if h.cfg != nil && h.cfg.Security.AccessTokenLifetime > 0 && lifetime > h.cfg.Security.AccessTokenLifetime {
		lifetime = h.cfg.Security.AccessTokenLifetime
	}
	if lifetime <= 0 {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token is expired or revoked")
		return
	}
	if h.oidcHandler == nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}
	tokenType := subject.TokenType
	if tokenType == "" {
		tokenType = boundTokenType(client)
	}
	if dpopJKT != "" {
		tokenType = "DPoP"
	}
	accessToken, err := h.oidcHandler.CreateAccessTokenJWT(
		r.Context(), client.ID, subject.UserID, strings.Join(scopes, " "), tokenType, lifetime,
		subject.OrgID, h.orgSlug(subject.OrgID), subject.Resource, subject.Act, extra,
	)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}
	jkt := subject.DPoPJKT
	if dpopJKT != "" {
		jkt = dpopJKT
	}
	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  client.ID,
		UserID:    subject.UserID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   jkt,
		Resource:  subject.Resource,
		OrgID:     subject.OrgID,
		Act:       subject.Act,
		ExpiresAt: time.Now().Add(lifetime),
	}
	h.stampCert(r, accessTok)
	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        tokenType,
		"expires_in":        int(lifetime.Seconds()),
		"scope":             strings.Join(scopes, " "),
	})
}

func customClaims(raw string) (map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 4096 {
		return nil, errClaim("claims is too large")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, errClaim("claims must be a JSON object")
	}
	if len(parsed) > maxCustomClaims {
		return nil, errClaim("claims has too many keys")
	}
	out := make(map[string]any, len(parsed))
	for name, value := range parsed {
		if !validClaimName(name) {
			return nil, errClaim("claim name is invalid")
		}
		if reservedAccessClaim(name) {
			return nil, errClaim("claim " + name + " is reserved")
		}
		clean, ok := claimValue(value)
		if !ok {
			return nil, errClaim("claim " + name + " must be a string, number, or boolean")
		}
		out[name] = clean
	}
	return out, nil
}

func validClaimName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, r := range name {
		if i == 0 && !unicode.IsLetter(r) {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

func reservedAccessClaim(name string) bool {
	switch name {
	case "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "client_id", "azp", "scope",
		"org_id", "org_slug", "org_role", "act", "nonce", "sid", "auth_time", "cnf":
		return true
	default:
		return false
	}
}

func claimValue(value any) (any, bool) {
	switch v := value.(type) {
	case string:
		if len(v) > maxClaimString {
			return nil, false
		}
		return v, true
	case bool:
		return v, true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, false
		}
		return v, true
	default:
		return nil, false
	}
}

type claimError string

func (e claimError) Error() string { return string(e) }

func errClaim(text string) error { return claimError(text) }
