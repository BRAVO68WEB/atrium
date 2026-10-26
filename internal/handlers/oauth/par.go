package oauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

// parMayMintRedirect is RFC 9126 section 2.4. An authenticated confidential
// client may name a redirect URI in this pushed request that was not
// registered ahead of time. A public client may not.
func parMayMintRedirect(client *models.Client, redirectURI string) bool {
	defer telemetry.Step("oauth.parMayMintRedirect")()
	if client == nil || client.TokenEndpointAuthMethod == "" || client.TokenEndpointAuthMethod == "none" {
		return false
	}
	switch client.TokenEndpointAuthMethod {
	case "client_secret_basic", "client_secret_post", "client_secret_jwt":
		if client.Secret == "" {
			return false
		}
	}
	return isValidURI(redirectURI)
}

// applyJARParams copies the request object over the authorization fields.
// A field the object omits is removed, so an outer copy cannot supply it.
func applyJARParams(form url.Values, claims map[string]string) {
	defer telemetry.Step("oauth.applyJARParams")()
	authoritative := []string{
		"response_type", "redirect_uri", "scope", "state", "nonce",
		"response_mode", "code_challenge", "code_challenge_method",
	}
	seen := map[string]bool{}
	for _, key := range authoritative {
		seen[key] = true
		if claims[key] != "" {
			form.Set(key, claims[key])
			continue
		}
		form.Del(key)
	}
	for key, value := range claims {
		if seen[key] || key == "client_id" || value == "" {
			continue
		}
		if form.Get(key) == "" {
			form.Set(key, value)
		}
	}
}

func (h *Handler) HandlePAR(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandlePAR")()
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Failed to parse request",
		})
		return
	}

	// Check for duplicate parameters
	if hasDuplicateParams(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Duplicate parameters are not allowed",
		})
		return
	}
	if credentialsInURI(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Client credentials must not be in the request URI",
		})
		return
	}

	clientID, clientSecret, authErr := h.credentials(r)
	if authErr != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Check for JAR request parameter
	requestJWT := r.Form.Get("request")
	if requestJWT != "" {
		// Parse JWT claims to get client_id if not in form
		if clientID == "" {
			// Quick parse to get client_id from JWT
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())
			token, _, err := parser.ParseUnverified(requestJWT, jwt.MapClaims{})
			if err == nil {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if cid, ok := claims["client_id"].(string); ok {
						clientID = cid
					}
				}
			}
		}
	}

	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_client",
			"error_description": "Client not found",
		})
		return
	}

	if authenticateClient(client, clientID, clientSecret, false) != "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	if strings.TrimSpace(client.RequestObjectSigningAlg) != "" && requestJWT == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "request object is required",
		})
		return
	}

	// Parse JAR request object if present
	if requestJWT != "" && h.jarSvc != nil {
		claims, err := h.jarSvc.ValidateRequestObject(requestJWT, client)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request_object",
				"error_description": "Invalid request JWT: " + err.Error(),
			})
			return
		}

		// The request object is the authorization request. An outer value does
		// not fill a parameter the object omitted.
		applyJARParams(r.Form, claims)
	}

	responseType := r.Form.Get("response_type")
	if responseType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "response_type is required",
		})
		return
	}

	if !validResponseTypes[responseType] {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_response_type",
			"error_description": "Unsupported response_type: " + responseType,
		})
		return
	}

	redirectURI := r.Form.Get("redirect_uri")
	if redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "redirect_uri is required",
		})
		return
	}

	if !isValidRedirectURI(redirectURI, client.RedirectURIs) && !parMayMintRedirect(client, redirectURI) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Invalid redirect_uri",
		})
		return
	}
	if !clientAllowsResponseType(client.GrantTypes, responseType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unauthorized_client",
			"error_description": "Client is not allowed this response_type",
		})
		return
	}

	scope := r.Form.Get("scope")
	state := r.Form.Get("state")
	codeChallenge := r.Form.Get("code_challenge")
	codeChallengeMethod := r.Form.Get("code_challenge_method")

	// PKCE validation (optional for conformance testing)
	needsCode := responseHas(responseType, "code")
	if needsCode && codeChallenge != "" {
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "Only S256 and plain code_challenge_method are supported",
			})
			return
		}
		if codeChallengeMethod == "plain" && (h.cfg == nil || !h.cfg.Security.AllowPlainPKCE) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "plain PKCE is disabled",
			})
			return
		}
	}
	if needsCode && h.cfg != nil && h.cfg.Security.RequirePKCE && codeChallenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "code_challenge is required",
		})
		return
	}

	requestParams := map[string]string{
		"response_type": responseType,
		"client_id":     clientID,
		"redirect_uri":  redirectURI,
		"scope":         scope,
	}
	if state != "" {
		requestParams["state"] = state
	}
	if codeChallenge != "" {
		requestParams["code_challenge"] = codeChallenge
		requestParams["code_challenge_method"] = codeChallengeMethod
	}

	// Copy all form params
	for key, values := range r.Form {
		if _, exists := requestParams[key]; !exists {
			requestParams[key] = values[0]
		}
	}

	requestParamsJSON, err := json.Marshal(requestParams)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to marshal request parameters",
		})
		return
	}

	requestURI, err := crypto.GenerateRequestURI()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to generate request URI",
		})
		return
	}

	par := &models.PushedAuthRequest{
		RequestURI:    requestURI,
		ClientID:      clientID,
		RequestParams: string(requestParamsJSON),
		ExpiresAt:     time.Now().Add(h.cfg.Security.RequestURILifetime),
	}

	if err := h.parRepo.Save(par); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to save pushed authorization request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"request_uri": requestURI,
		"expires_in":  int(h.cfg.Security.RequestURILifetime.Seconds()),
	})
}
