package oauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

func (h *Handler) handleClientCredentialsToken(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.handleClientCredentialsToken")()
	clientID, clientSecret := presentedClient(r)

	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client credentials required")
		return
	}

	client, ok := h.requireClient(w, clientID, "", http.StatusUnauthorized)
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

	// Validate mTLS only when client auth method requires it
	if client.TokenEndpointAuthMethod == "tls_client_auth" || client.TokenEndpointAuthMethod == "self_signed_tls_client_auth" {
		cert := h.mtlsSvc.ExtractClientCertificate(r)
		if cert == nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client certificate required")
			return
		}
		if err := h.mtlsSvc.ValidateClientCertificate(cert, nil); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Invalid client certificate: "+err.Error())
			return
		}
	}

	hasGrantType := false
	for _, gt := range client.GrantTypes {
		if gt == "client_credentials" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "Client not authorized for client_credentials grant")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}

	scopes, err := service.AllowedScopes(r.Form.Get("scope"), client.Scopes)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}

	tokenType := boundTokenType(client)
	orgID, orgSlug, orgCode, orgDesc := h.applyOrg(client, nil, "")
	if orgCode != "" {
		writeTokenError(w, http.StatusBadRequest, orgCode, orgDesc)
		return
	}

	resource := r.Form.Get("resource")
	accessToken, err := h.issueAccessTokenFor(clientID, "", strings.Join(scopes, " "), tokenType, orgID, orgSlug, resource, "")
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scopes:    scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		Resource:  resource,
		OrgID:     orgID,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token: "+err.Error())
		return
	}

	writeTokenResponse(w, accessToken, "", int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(scopes, " "))
}
