package oauth

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	responseMode := r.URL.Query().Get("response_mode")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	prompt := r.URL.Query().Get("prompt")
	loginHint := r.URL.Query().Get("login_hint")
	resource := r.URL.Query().Get("resource")
	organization := r.URL.Query().Get("organization")
	requestedActor := strings.TrimSpace(r.URL.Query().Get("requested_actor"))
	requestURI := r.URL.Query().Get("request_uri")
	request := r.URL.Query().Get("request")

	// Handle JAR - parse request JWT parameter
	if request != "" {
		if clientID == "" {
			// Quick parse to get client_id from JWT
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())
			token, _, err := parser.ParseUnverified(request, jwt.MapClaims{})
			if err == nil {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					if cid, ok := claims["client_id"].(string); ok {
						clientID = cid
					}
				}
			}
		}

		if clientID != "" {
			client, code, _ := h.resolveClient(clientID, redirectURI)
			if code == "" && client != nil && h.jarSvc != nil {
				claims, err := h.jarSvc.ValidateRequestObject(request, client)
				if err != nil {
					writeOAuthError(w, http.StatusBadRequest, "invalid_request_object", "Invalid request JWT: "+err.Error(), "")
					return
				}

				// Query values fill blanks. The request object keeps its code challenge.
				if v, ok := claims["client_id"]; ok && clientID == "" {
					clientID = v
				}
				if v, ok := claims["redirect_uri"]; ok && redirectURI == "" {
					redirectURI = v
				}
				if v, ok := claims["response_type"]; ok && responseType == "" {
					responseType = v
				}
				if v, ok := claims["scope"]; ok && scope == "" {
					scope = v
				}
				if v, ok := claims["state"]; ok && state == "" {
					state = v
				}
				if v, ok := claims["nonce"]; ok && nonce == "" {
					nonce = v
				}
				if v, ok := claims["code_challenge"]; ok && v != "" {
					codeChallenge = v
				}
				if v, ok := claims["code_challenge_method"]; ok && v != "" {
					codeChallengeMethod = v
				}
				if v, ok := claims["prompt"]; ok && prompt == "" {
					prompt = v
				}
				if v, ok := claims["login_hint"]; ok && loginHint == "" {
					loginHint = v
				}
				if v, ok := claims["resource"]; ok && resource == "" {
					resource = v
				}
				if v, ok := claims["organization"]; ok && organization == "" {
					organization = v
				}
				if v, ok := claims["requested_actor"]; ok && requestedActor == "" {
					requestedActor = strings.TrimSpace(v)
				}
			}
		}
	}

	// Handle PAR - fetch stored parameters from request_uri
	if requestURI != "" {
		par, err := h.parRepo.GetByRequestURI(requestURI)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid request_uri", state)
			return
		}

		if time.Now().After(par.ExpiresAt) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request_uri expired", state)
			return
		}

		var params map[string]string
		if err := json.Unmarshal([]byte(par.RequestParams), &params); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to parse stored request", state)
			return
		}

		if v, ok := params["client_id"]; ok && clientID == "" {
			clientID = v
		}
		if v, ok := params["redirect_uri"]; ok && redirectURI == "" {
			redirectURI = v
		}
		if v, ok := params["response_type"]; ok && responseType == "" {
			responseType = v
		}
		if v, ok := params["scope"]; ok && scope == "" {
			scope = v
		}
		if v, ok := params["state"]; ok && state == "" {
			state = v
		}
		if v, ok := params["nonce"]; ok && nonce == "" {
			nonce = v
		}
		if v, ok := params["code_challenge"]; ok && v != "" {
			codeChallenge = v
		}
		if v, ok := params["code_challenge_method"]; ok && v != "" {
			codeChallengeMethod = v
		}
		if v, ok := params["prompt"]; ok && prompt == "" {
			prompt = v
		}
		if v, ok := params["login_hint"]; ok && loginHint == "" {
			loginHint = v
		}
		if v, ok := params["resource"]; ok && resource == "" {
			resource = v
		}
		if v, ok := params["organization"]; ok && organization == "" {
			organization = v
		}
		if v, ok := params["requested_actor"]; ok && requestedActor == "" {
			requestedActor = strings.TrimSpace(v)
		}
	}

	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required", "")
		return
	}

	client, code, desc := h.resolveClient(clientID, redirectURI)
	if code != "" {
		writeOAuthError(w, http.StatusBadRequest, code, desc, state)
		return
	}

	if !validResponseTypes[responseType] {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "Unsupported response_type: "+responseType, state)
		return
	}

	// RFC 6749: redirect_uri is required if multiple URIs are registered
	if redirectURI == "" && len(client.RedirectURIs) > 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required when multiple redirect URIs are registered", state)
		return
	}

	// If only one URI registered and none provided, use the registered one
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}

	if !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri", state)
		return
	}

	// PKCE validation (optional for conformance testing)
	needsCode := responseHas(responseType, "code")
	if needsCode && codeChallenge != "" {
		// Default to S256 if not specified
		if codeChallengeMethod == "" {
			codeChallengeMethod = "S256"
		}
		// Allow S256 and plain
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Only S256 and plain code_challenge_method are supported", state)
			return
		}
	}
	if needsCode && h.cfg != nil && h.cfg.Security.RequirePKCE && codeChallenge == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required", state)
		return
	}
	if IsOutOfBandRedirect(redirectURI) {
		if responseType != "code" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "out-of-band redirect requires response_type code", state)
			return
		}
		if codeChallenge == "" || codeChallengeMethod != "S256" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "out-of-band redirect requires S256 PKCE", state)
			return
		}
	}
	if requestedActor != "" {
		if responseType != "code" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "requested_actor requires response_type code", state)
			return
		}
		if codeChallenge == "" || codeChallengeMethod != "S256" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "requested_actor requires S256 PKCE", state)
			return
		}
		actor, err := h.clientRepo.GetByID(requestedActor)
		if err != nil || actor == nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "requested_actor is not recognized", state)
			return
		}
	}
	if !clientAllowsResponseType(client.GrantTypes, responseType) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "Client is not allowed this response_type", state)
		return
	}

	// Nonce is required when the response type includes id_token.
	needsIDToken := responseHas(responseType, "id_token")
	if needsIDToken && nonce == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "nonce is required for implicit/hybrid flows", state)
		return
	}

	session := h.getSession(r)

	// prompt=none: no UI allowed, must already be authenticated and consented
	if prompt == "none" {
		if session == nil || !session.Authenticated {
			writeOAuthError(w, http.StatusFound, "login_required", "User must be authenticated", state)
			return
		}
		if requestedActor != "" || !h.hasConsented(session.UserID, clientID, scope) {
			writeOAuthError(w, http.StatusFound, "consent_required", "User consent required", state)
			return
		}
		needs, err := h.needsOrgChoice(client, session.UserID, organization)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to load organizations", state)
			return
		}
		if needs {
			writeOAuthError(w, http.StatusFound, "interaction_required", "Organization selection required", state)
			return
		}
		// Proceed directly
		h.issueAuthorizationResponse(w, r, client, session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource, organization, requestedActor)
		return
	}

	// prompt=login: force re-authentication
	if prompt == "login" {
		h.clearSession(w, r)
		loginURL := "/login?" + r.URL.RawQuery
		if loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Not authenticated: redirect to login
	if session == nil || !session.Authenticated {
		loginURL := "/login?" + r.URL.RawQuery
		if loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// MFA check
	if !session.MFAVerified && h.cfg.Security.MFA.Required {
		mfaURL := "/login/mfa?" + r.URL.RawQuery
		http.Redirect(w, r, mfaURL, http.StatusFound)
		return
	}

	needs, err := h.needsOrgChoice(client, session.UserID, organization)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to load organizations", state)
		return
	}
	if needs {
		http.Redirect(w, r, "/organization?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	// A named actor is confirmed on its own. The consent POST leaves a
	// one-time grant so this request can finish without asking again.
	if requestedActor != "" {
		if !h.takeActorConsent(session.ID, clientID, requestedActor) {
			http.Redirect(w, r, "/consent?"+r.URL.RawQuery, http.StatusFound)
			return
		}
	} else if prompt == "consent" || !h.hasConsented(session.UserID, clientID, scope) {
		consentURL := "/consent?" + r.URL.RawQuery
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	h.issueAuthorizationResponse(w, r, client, session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource, organization, requestedActor)
}

// ApplyRequestObject fills empty authorize fields from a signed request.
// The code challenge in that request wins over a query value.
func (h *Handler) ApplyRequestObject(params map[string]string) {
	if h == nil || h.jarSvc == nil || strings.TrimSpace(params["request"]) == "" {
		return
	}
	client, _, _ := h.resolveClient(params["client_id"], params["redirect_uri"])
	if client == nil {
		return
	}
	claims, err := h.jarSvc.ValidateRequestObject(params["request"], client)
	if err != nil {
		return
	}
	for key, value := range claims {
		if value == "" {
			continue
		}
		if key == "code_challenge" || key == "code_challenge_method" || params[key] == "" {
			params[key] = value
		}
	}
}

func (h *Handler) issueAuthorizationResponse(w http.ResponseWriter, r *http.Request, client *models.Client, session *Session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource, organization, requestedActor string) {
	scopes := crypto.NormalizeScopes(scope)
	hasOpenID := containsScope(scopes, "openid")
	var account *models.User
	if h.userRepo != nil && session != nil {
		account, _ = h.userRepo.GetByID(session.UserID)
	}
	orgID, orgSlug, orgCode, orgDesc := h.applyOrg(client, account, organization)
	if orgCode == "access_denied" && redirectURI != "" {
		if IsOutOfBandRedirect(redirectURI) {
			h.RenderOutOfBand(w, client.ID, "", state, "access_denied", "User is not a member of the organization")
			return
		}
		errorURL := redirectURI
		if strings.Contains(errorURL, "?") {
			errorURL += "&"
		} else {
			errorURL += "?"
		}
		errorURL += "error=access_denied&error_description=User+is+not+a+member+of+the+organization"
		if state != "" {
			errorURL += "&state=" + url.QueryEscape(state)
		}
		http.Redirect(w, r, errorURL, http.StatusFound)
		return
	}
	if orgCode != "" {
		writeOAuthError(w, http.StatusBadRequest, orgCode, orgDesc, state)
		return
	}

	var code string
	var accessToken string
	var idToken string
	var err error

	needsCode := responseHas(responseType, "code")
	needsToken := responseHas(responseType, "token")
	needsIDToken := responseHas(responseType, "id_token")

	if needsCode {
		code, err = crypto.GenerateAuthorizationCode()
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate authorization code", state)
			return
		}

		familyID := uuid.New().String()
		authCode := &models.AuthorizationCode{
			Code:                code,
			ClientID:            client.ID,
			UserID:              session.UserID,
			RedirectURI:         redirectURI,
			Scopes:              scopes,
			Resource:            resource,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			FamilyID:            familyID,
			SessionID:           session.ID,
			AuthTime:            session.AuthTime,
			OrgID:               orgID,
			RequestedActor:      requestedActor,
			ExpiresAt:           time.Now().Add(h.cfg.Security.AuthorizationCodeLifetime),
			Used:                false,
		}

		if err := h.authCodeRepo.Save(authCode); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to save authorization code", state)
			return
		}
	}

	if needsToken {
		accessToken, err = h.issueAccessTokenFor(client.ID, session.UserID, scope, "Bearer", orgID, orgSlug, resource, "")
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token", state)
			return
		}

		accessTok := &models.AccessToken{
			Token:     accessToken,
			ClientID:  client.ID,
			UserID:    session.UserID,
			Scopes:    scopes,
			Resource:  resource,
			TokenType: "Bearer",
			OrgID:     orgID,
			ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
		}

		if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to save access token", state)
			return
		}
	}

	if h.sessions != nil && session.ID != "" {
		prior, _ := h.sessions.Clients(session.ID)
		_ = h.sessions.RecordClient(session.ID, client.ID)
		prompt := r.URL.Query().Get("prompt")
		if prompt == "" && r.Form != nil {
			prompt = r.Form.Get("prompt")
		}
		crossClient := false
		for _, id := range prior {
			if id != "" && id != client.ID {
				crossClient = true
				break
			}
		}
		if h.hooks != nil && (crossClient || prompt == "none") {
			payload := map[string]any{
				"user_id": session.UserID, "username": session.Username,
				"session_id": session.ID, "client_id": client.ID,
				"prompt": prompt, "scope": scope,
			}
			if orgID != "" {
				payload["org_id"] = orgID
			}
			h.hooks.Emit(service.EventSSOSession, payload)
		}
	}

	if needsIDToken && hasOpenID && h.oidcHandler != nil {
		idToken, err = h.oidcHandler.CreateIDToken(client.ID, session.UserID, nonce, scopes, oidc.IDTokenExtra{SID: session.ID, AuthTime: session.AuthTime, OrgID: orgID, OrgSlug: orgSlug})
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token", state)
			return
		}
	}

	// Build response parameters
	params := url.Values{}
	if needsCode {
		params.Set("code", code)
	}
	if needsToken {
		params.Set("access_token", accessToken)
		params.Set("token_type", "Bearer")
		params.Set("expires_in", fmt.Sprintf("%d", int(h.cfg.Security.AccessTokenLifetime.Seconds())))
	}
	if needsIDToken && idToken != "" {
		params.Set("id_token", idToken)
	}
	if state != "" {
		params.Set("state", state)
	}
	if h.cfg != nil && h.cfg.Security.Issuer != "" {
		params.Set("iss", h.cfg.Security.Issuer)
	}

	if IsOutOfBandRedirect(redirectURI) {
		h.RenderOutOfBand(w, client.ID, code, state, "", "")
		return
	}

	// Handle response_mode
	if responseMode == "form_post" {
		// Return HTML form that auto-submits to redirect_uri
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Submit This Form</title></head>
<body onload="javascript:document.forms[0].submit()">
<form method="post" action="%s">`, html.EscapeString(redirectURI))
		for key, values := range params {
			for _, value := range values {
				_, _ = fmt.Fprintf(w, `<input type="hidden" name="%s" value="%s"/>`, html.EscapeString(key), html.EscapeString(value))
			}
		}
		_, _ = fmt.Fprintf(w, `</form></body></html>`)
		return
	}

	// Default: fragment response for implicit/hybrid, query for code
	if responseType == "none" {
		redirectTo := redirectURI
		if len(params) > 0 {
			if strings.Contains(redirectTo, "?") {
				redirectTo += "&" + params.Encode()
			} else {
				redirectTo += "?" + params.Encode()
			}
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	if needsCode && !needsToken && !needsIDToken {
		// Code only - use query parameter
		redirectTo := redirectURI
		if strings.Contains(redirectTo, "?") {
			redirectTo += "&" + params.Encode()
		} else {
			redirectTo += "?" + params.Encode()
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	// Implicit/hybrid - use fragment
	redirectTo := redirectURI + "#" + params.Encode()
	http.Redirect(w, r, redirectTo, http.StatusFound)
}
