package oauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) handlePasswordToken(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.handlePasswordToken")()
	clientID, clientSecret := presentedClient(r)

	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client credentials required")
		return
	}

	client, ok := h.requireClient(r.Context(), w, clientID, "", http.StatusUnauthorized)
	if !ok {
		return
	}

	switch authenticateClient(client, clientID, clientSecret, false) {
	case "":
	case "missing_secret":
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client credentials required")
		return
	default:
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client secret")
		return
	}

	hasGrantType := false
	for _, gt := range client.GrantTypes {
		if gt == "password" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client not authorized for password grant")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}

	if h.userSvc == nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Password hasher is not configured")
		return
	}

	user, err := h.userSvc.Authenticate(username, password)
	if err != nil {
		if existing, lookupErr := h.userSvc.FindByLogin(username); lookupErr == nil && h.logins != nil {
			h.logins.Record(existing, r, false, false)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid username or password")
		return
	}
	if h.logins != nil {
		h.logins.Record(user, r, true, false)
	}

	scopes, err := service.AllowedScopes(r.Form.Get("scope"), client.Scopes)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}

	orgID, orgSlug, orgCode, orgDesc := h.applyOrg(client, user, r.Form.Get("organization"))
	if orgCode == "access_denied" {
		writeTokenError(w, http.StatusBadRequest, "access_denied", orgDesc)
		return
	}
	if orgCode != "" {
		writeTokenError(w, http.StatusBadRequest, orgCode, orgDesc)
		return
	}

	resource := r.Form.Get("resource")
	accessToken, err := h.issueAccessTokenFor(r.Context(), clientID, user.ID, strings.Join(scopes, " "), tokenType, orgID, orgSlug, resource, "")
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    user.ID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		OrgID:     orgID,
		Resource:  resource,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    clientID,
		UserID:      user.ID,
		OrgID:       orgID,
		Resource:    resource,
		Scopes:      scopes,
		FamilyID:    uuid.New().String(),
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	var idToken string
	if containsScope(scopes, "openid") && h.oidcHandler != nil {
		idToken, err = h.oidcHandler.CreateIDToken(r.Context(), clientID, user.ID, "", scopes, oidc.IDTokenExtra{OrgID: orgID, OrgSlug: orgSlug})
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token")
			return
		}
	}

	writeOIDCTokenResponse(w, accessToken, refreshToken, idToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(scopes, " "))
}
