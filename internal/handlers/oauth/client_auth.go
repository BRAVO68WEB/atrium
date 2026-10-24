package oauth

import (
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func presentedClient(r *http.Request) (string, string) {
	defer telemetry.Step("oauth.presentedClient")()
	id, secret, ok := r.BasicAuth()
	if ok {
		return id, secret
	}
	return r.Form.Get("client_id"), r.Form.Get("client_secret")
}

// authenticateClient checks presented credentials against client.
// token_endpoint_auth_method none succeeds without a secret.
// matchID is set when client was loaded from a stored grant, not from the presented id.
// The result is empty on success, or mismatch, missing_secret, or bad_secret.
func authenticateClient(client *models.Client, presentedID, presentedSecret string, matchID bool) string {
	defer telemetry.Step("oauth.authenticateClient")()
	if client == nil {
		return "bad_secret"
	}
	if client.TokenEndpointAuthMethod == "none" {
		return ""
	}
	if matchID && presentedID != client.ID {
		return "mismatch"
	}
	if presentedSecret == "" {
		return "missing_secret"
	}
	if !crypto.SecretEqual(presentedSecret, client.Secret) {
		return "bad_secret"
	}
	return ""
}

// tokenCaller authenticates the client at the token, revocation, and exchange endpoints.
func (h *Handler) tokenCaller(w http.ResponseWriter, r *http.Request) (*models.Client, bool) {
	defer telemetry.Step("oauth.Handler.tokenCaller")()
	clientID, clientSecret := presentedClient(r)
	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client authentication required")
		return nil, false
	}
	client, ok := h.requireClient(w, clientID, "", http.StatusUnauthorized)
	if !ok {
		return nil, false
	}
	if authenticateClient(client, clientID, clientSecret, false) != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return nil, false
	}
	return client, true
}
