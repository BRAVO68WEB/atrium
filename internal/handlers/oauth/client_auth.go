package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func credentialsInURI(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	query := r.URL.Query()
	return query.Get("client_id") != "" || query.Get("client_secret") != ""
}

// credentials returns the authenticated client id and secret.
// A client_assertion replaces the shared secret. The returned secret is the
// stored secret so the existing comparison still succeeds.
func (h *Handler) credentials(r *http.Request) (string, string, error) {
	defer telemetry.Step("oauth.Handler.credentials")()
	raw := ""
	if r != nil && r.Form != nil {
		raw = strings.TrimSpace(r.Form.Get("client_assertion"))
	}
	if raw == "" {
		id, secret := presentedClient(r)
		return id, secret, nil
	}
	client, err := h.verifyClientAssertion(r, raw)
	if err != nil {
		return "", "", err
	}
	return client.ID, client.Secret, nil
}

func (h *Handler) verifyClientAssertion(r *http.Request, raw string) (*models.Client, error) {
	defer telemetry.Step("oauth.Handler.verifyClientAssertion")()
	parser := strings.TrimSpace(r.Form.Get("client_assertion_type"))
	unverifiedID := strings.TrimSpace(r.Form.Get("client_id"))
	clientID := unverifiedID
	if clientID == "" {
		clientID = assertionSubject(raw)
	}
	if clientID == "" || h.clientRepo == nil {
		return nil, errInvalidAssertion
	}
	client, err := h.clientRepo.GetByID(clientID)
	if err != nil || client == nil {
		return nil, errInvalidAssertion
	}
	if unverifiedID != "" && unverifiedID != client.ID {
		return nil, errInvalidAssertion
	}
	issuer := ""
	if h.cfg != nil {
		issuer = h.cfg.Security.Issuer
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requestURL := service.RequestURL(scheme, r.Host, r.URL.Path)
	if err := service.VerifyClientAssertion(r.Context(), h.cimd, h.jarSvc, client, raw, parser, issuer, requestURL); err != nil {
		return nil, errInvalidAssertion
	}
	return client, nil
}

func assertionSubject(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Sub
}

var errInvalidAssertion = errors.New("invalid client assertion")

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
	clientID, clientSecret, authErr := h.credentials(r)
	if authErr != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return nil, false
	}
	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client authentication required")
		return nil, false
	}
	client, ok := h.requireClient(r.Context(), w, clientID, "", http.StatusUnauthorized)
	if !ok {
		return nil, false
	}
	if authenticateClient(client, clientID, clientSecret, false) != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return nil, false
	}
	return client, true
}
