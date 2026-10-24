package oauth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

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

	clientID, clientSecret := presentedClient(r)

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

		// Merge JWT claims with form params (form params take precedence)
		for k, v := range claims {
			if r.Form.Get(k) == "" {
				r.Form.Set(k, v)
			}
		}
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
	if redirectURI == "" && len(client.RedirectURIs) > 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "redirect_uri is required when multiple redirect URIs are registered",
		})
		return
	}
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}

	if !isValidRedirectURI(redirectURI, client.RedirectURIs) {
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
