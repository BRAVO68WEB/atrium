package oauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func (h *Handler) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.handleRefreshToken")()
	refreshTokenStr := r.Form.Get("refresh_token")
	if refreshTokenStr == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	refreshToken, err := h.tokenRepo.GetRefreshToken(refreshTokenStr)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
		return
	}

	// Refresh token reuse detection - revoke entire grant family
	if refreshToken.Revoked {
		if refreshToken.FamilyID != "" {
			_ = h.tokenRepo.RevokeFamily(refreshToken.FamilyID)
		} else {
			_ = h.tokenRepo.RevokeAllForClient(refreshToken.ClientID, refreshToken.UserID)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token revoked")
		return
	}

	if !refreshToken.ExpiresAt.IsZero() && time.Now().After(refreshToken.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Refresh token expired")
		return
	}

	clientID, clientSecret := presentedClient(r)

	client, ok := h.requireClient(r.Context(), w, refreshToken.ClientID, "", http.StatusBadRequest)
	if !ok {
		return
	}

	if authenticateClient(client, clientID, clientSecret, true) != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}

	boundJKT := ""
	if old, err := h.tokenRepo.GetAccessToken(refreshToken.AccessToken); err == nil {
		boundJKT = old.DPoPJKT
	}
	dpopJKT, ok := h.boundRefreshDPoP(w, r, client, boundJKT)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)
	if dpopJKT != "" {
		tokenType = "DPoP"
	}
	orgSlug := h.orgSlug(refreshToken.OrgID)
	scopes, err := h.narrowScopes(refreshToken.UserID, refreshToken.OrgID, refreshToken.Scopes)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to resolve scopes")
		return
	}
	refreshToken.Scopes = scopes

	newAccessToken, err := h.issueAccessTokenFor(r.Context(), refreshToken.ClientID, refreshToken.UserID, strings.Join(refreshToken.Scopes, " "), tokenType, refreshToken.OrgID, orgSlug, refreshToken.Resource, refreshToken.Act)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	newRefreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     newAccessToken,
		ClientID:  refreshToken.ClientID,
		UserID:    refreshToken.UserID,
		Scopes:    refreshToken.Scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		Resource:  refreshToken.Resource,
		OrgID:     refreshToken.OrgID,
		Act:       refreshToken.Act,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	familyID := refreshToken.FamilyID
	if familyID == "" {
		familyID = uuid.New().String()
	}
	newRefreshTok := &models.RefreshToken{
		Token:       newRefreshToken,
		AccessToken: newAccessToken,
		ClientID:    refreshToken.ClientID,
		UserID:      refreshToken.UserID,
		OrgID:       refreshToken.OrgID,
		Resource:    refreshToken.Resource,
		Act:         refreshToken.Act,
		Scopes:      refreshToken.Scopes,
		FamilyID:    familyID,
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(newRefreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}
	_ = h.tokenRepo.RevokeAccessToken(refreshToken.AccessToken)
	_ = h.tokenRepo.RevokeRefreshToken(refreshTokenStr)

	writeTokenResponse(w, newAccessToken, newRefreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(refreshToken.Scopes, " "))
}
