package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

func (h *Handler) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.handleTokenExchange")()
	client, ok := h.tokenCaller(w, r)
	if !ok {
		return
	}
	clientID := client.ID

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	if h.cfg != nil && h.cfg.XAA.Enabled && r.Form.Get("requested_token_type") == config.XAAIDJAGTokenType {
		h.handleIDJAGExchange(w, r, client)
		return
	}
	tokenType := boundTokenType(client)

	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")

	if subjectToken == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}

	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Unsupported subject_token_type: "+subjectTokenType)
		return
	}

	subjectTokenInfo, err := h.tokenRepo.GetAccessToken(subjectToken)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid subject_token")
		return
	}

	if subjectTokenInfo.Revoked || time.Now().After(subjectTokenInfo.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token is expired or revoked")
		return
	}
	if !service.HasGrant(client.GrantTypes, "urn:ietf:params:oauth:grant-type:token-exchange") {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client is not authorized for token exchange")
		return
	}
	if subjectTokenInfo.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "subject_token was not issued to this client")
		return
	}

	scopes, err := service.AllowedScopes(r.Form.Get("scope"), subjectTokenInfo.Scopes)
	if err != nil || len(scopes) == 0 {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "Scope is not allowed")
		return
	}

	accessToken, err := h.issueAccessToken(r.Context(), clientID, subjectTokenInfo.UserID, strings.Join(scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    subjectTokenInfo.UserID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":      accessToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        tokenType,
		"expires_in":        int(h.cfg.Security.AccessTokenLifetime.Seconds()),
		"scope":             strings.Join(scopes, " "),
	})
}

func (h *Handler) handleIDJAGExchange(w http.ResponseWriter, r *http.Request, client *models.Client) {
	defer telemetry.Step("oauth.Handler.handleIDJAGExchange")()
	if !service.HasGrant(client.GrantTypes, "urn:ietf:params:oauth:grant-type:token-exchange") {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client is not authorized for token exchange")
		return
	}
	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")
	if subjectToken == "" || subjectTokenType == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "subject_token and subject_token_type are required")
		return
	}
	if subjectTokenType != "urn:ietf:params:oauth:token-type:id_token" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Unsupported subject_token_type: "+subjectTokenType)
		return
	}
	if h.oidcHandler == nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to verify the ID token")
		return
	}
	compact, scope, expiresIn, err := h.xaa().Issue(
		r.Context(), client.ID, subjectToken, r.Form.Get("audience"), r.Form.Get("scope"),
		h.oidcHandler.ParseSignedToken, h.oidcHandler.SignRSA,
	)
	if err != nil {
		writeGrantError(w, err)
		return
	}
	writeIDJAG(w, compact, scope, expiresIn)
}

func writeGrantError(w http.ResponseWriter, err error) {
	defer telemetry.Step("oauth.writeGrantError")()
	var failure *service.GrantFailure
	if errors.As(err, &failure) {
		writeTokenError(w, failure.Status, failure.Code, failure.Description)
		return
	}
	writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to complete the grant")
}

func writeIDJAG(w http.ResponseWriter, token, scope string, expiresIn int) {
	defer telemetry.Step("oauth.writeIDJAG")()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	body := map[string]any{
		"access_token":      token,
		"issued_token_type": config.XAAIDJAGTokenType,
		"token_type":        "N_A",
		"expires_in":        expiresIn,
	}
	if scope != "" {
		body["scope"] = scope
	}
	_ = json.NewEncoder(w).Encode(body)
}
