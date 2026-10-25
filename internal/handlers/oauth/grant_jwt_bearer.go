package oauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func (h *Handler) handleJWTBearer(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.handleJWTBearer")()
	client, ok := h.tokenCaller(w, r)
	if !ok {
		return
	}
	if !service.HasGrant(client.GrantTypes, config.XAAJWTBearerGrant) {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client is not authorized for this grant")
		return
	}
	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	redeemed, err := h.xaa().Redeem(r.Context(), client.ID, r.Form.Get("assertion"))
	if err != nil {
		writeGrantError(w, err)
		return
	}
	tokenType := boundTokenType(client)
	scope := strings.Join(redeemed.Scopes, " ")
	accessToken, err := h.issueAccessToken(r.Context(), client.ID, redeemed.UserID, scope, tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}
	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  client.ID,
		UserID:    redeemed.UserID,
		Scopes:    redeemed.Scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}
	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}
	writeTokenResponse(w, accessToken, "", int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, scope)
}
