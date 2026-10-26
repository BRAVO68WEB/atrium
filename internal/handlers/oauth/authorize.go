package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleAuthorize")()
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request", "")
		return
	}
	if hasDuplicateParams(r) {
		h.rejectDuplicateAuthorize(w, r)
		return
	}
	clientID := firstOAuthParam(r, "client_id")
	redirectURI := firstOAuthParam(r, "redirect_uri")
	responseType := firstOAuthParam(r, "response_type")
	responseMode := firstOAuthParam(r, "response_mode")
	scope := firstOAuthParam(r, "scope")
	state := firstOAuthParam(r, "state")
	nonce := firstOAuthParam(r, "nonce")
	codeChallenge := firstOAuthParam(r, "code_challenge")
	codeChallengeMethod := firstOAuthParam(r, "code_challenge_method")
	prompt := firstOAuthParam(r, "prompt")
	loginHint := firstOAuthParam(r, "login_hint")
	resource := firstOAuthParam(r, "resource")
	organization := firstOAuthParam(r, "organization")
	requestedActor := strings.TrimSpace(firstOAuthParam(r, "requested_actor"))
	requestURI := firstOAuthParam(r, "request_uri")
	request := firstOAuthParam(r, "request")
	redirectFromPAR := false

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
			client, code, _ := h.resolveClient(r.Context(), clientID, redirectURI)
			if code == "" && client != nil && h.jarSvc != nil {
				claims, err := h.jarSvc.ValidateRequestObject(request, client)
				if err != nil {
					writeOAuthError(w, http.StatusBadRequest, "invalid_request_object", "Invalid request JWT: "+err.Error(), "")
					return
				}

				// The request object is the authorization request. client_id stays
				// the authenticated client. An outer value does not fill a blank.
				redirectURI = claims["redirect_uri"]
				responseType = claims["response_type"]
				scope = claims["scope"]
				state = claims["state"]
				nonce = claims["nonce"]
				codeChallenge = claims["code_challenge"]
				codeChallengeMethod = claims["code_challenge_method"]
				responseMode = claims["response_mode"]
				if v := claims["prompt"]; v != "" {
					prompt = v
				}
				if v := claims["login_hint"]; v != "" {
					loginHint = v
				}
				if v := claims["resource"]; v != "" {
					resource = v
				}
				if v := claims["organization"]; v != "" {
					organization = v
				}
				if v := strings.TrimSpace(claims["requested_actor"]); v != "" {
					requestedActor = v
				}
			}
		}
	}

	// Handle PAR - fetch stored parameters from request_uri
	if requestURI != "" {
		par, err := h.parRepo.GetByRequestURI(requestURI)
		if err != nil || par == nil {
			h.redirectUnknownRequestURI(w, r, clientID, "Invalid request_uri")
			return
		}

		if par.Used {
			h.redirectStoredRequestError(w, r, par, "Invalid request_uri")
			return
		}
		if time.Now().After(par.ExpiresAt) {
			h.redirectStoredRequestError(w, r, par, "request_uri expired")
			return
		}
		if clientID != "" && clientID != par.ClientID {
			h.redirectStoredRequestError(w, r, par, "client_id does not match the request_uri")
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
			redirectFromPAR = true
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
		if v, ok := params["response_mode"]; ok && responseMode == "" {
			responseMode = v
		}
	}

	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required", "")
		return
	}

	client, code, desc := h.resolveClient(r.Context(), clientID, redirectURI)
	if code != "" {
		writeOAuthError(w, http.StatusBadRequest, code, desc, state)
		return
	}

	if !validResponseTypes[responseType] {
		h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "unsupported_response_type", "Unsupported response_type: "+responseType)
		return
	}

	if redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required", state)
		return
	}

	if !isValidRedirectURI(redirectURI, client.RedirectURIs) && !(redirectFromPAR && parMayMintRedirect(client, redirectURI)) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri", state)
		return
	}

	if client.RequirePushedAuthorizationRequests && requestURI == "" {
		sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "invalid_request", "request_uri is required", state)
		return
	}
	if strings.TrimSpace(client.RequestObjectSigningAlg) != "" && request == "" && requestURI == "" {
		sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "invalid_request", "request object is required", state)
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
			h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "invalid_request", "Only S256 and plain code_challenge_method are supported")
			return
		}
		if codeChallengeMethod == "plain" && (h.cfg == nil || !h.cfg.Security.AllowPlainPKCE) {
			h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "invalid_request", "plain PKCE is disabled")
			return
		}
	}
	if needsCode && h.cfg != nil && h.cfg.Security.RequirePKCE && codeChallenge == "" {
		h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "invalid_request", "code_challenge is required")
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
			h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "invalid_request", "requested_actor requires response_type code")
			return
		}
		if codeChallenge == "" || codeChallengeMethod != "S256" {
			h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "invalid_request", "requested_actor requires S256 PKCE")
			return
		}
		actor, err := h.clientRepo.GetByID(requestedActor)
		if err != nil || actor == nil {
			h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "invalid_request", "requested_actor is not recognized")
			return
		}
	}
	if !clientAllowsResponseType(client.GrantTypes, responseType) {
		h.failAuthorize(w, r, client, redirectURI, responseType, responseMode, state, "unauthorized_client", "Client is not allowed this response_type")
		return
	}

	// Nonce is required when the response type includes id_token.
	needsIDToken := responseHas(responseType, "id_token")
	if needsIDToken && nonce == "" {
		sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "invalid_request", "nonce is required for implicit/hybrid flows", state)
		return
	}

	session := h.getSession(r)

	// prompt=none: no UI allowed, must already be authenticated and consented
	if prompt == "none" {
		if session == nil || !session.Authenticated {
			sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "login_required", "User must be authenticated", state)
			return
		}
		if requestedActor != "" || !h.hasConsented(session.UserID, clientID, scope) {
			sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "consent_required", "User consent required", state)
			return
		}
		needs, err := h.needsOrgChoice(client, session.UserID, organization)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to load organizations", state)
			return
		}
		if needs {
			sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "interaction_required", "Organization selection required", state)
			return
		}
		telemetry.Interaction("complete")
		h.issueAuthorizationResponse(w, r, client, session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource, organization, requestedActor, requestURI)
		return
	}

	// prompt=login: force re-authentication
	if prompt == "login" {
		telemetry.Interaction("login")
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
		telemetry.Interaction("login")
		loginURL := "/login?" + r.URL.RawQuery
		if loginHint != "" {
			loginURL += "&login_hint=" + url.QueryEscape(loginHint)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// MFA check
	if !session.MFAVerified && h.cfg.Security.MFA.Required {
		telemetry.Interaction("mfa")
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
		telemetry.Interaction("organization")
		http.Redirect(w, r, "/organization?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	// A named actor is confirmed on its own. The consent POST leaves a
	// one-time grant so this request can finish without asking again.
	if requestedActor != "" {
		if !h.takeActorConsent(session.ID, clientID, requestedActor) {
			telemetry.Interaction("consent")
			http.Redirect(w, r, "/consent?"+r.URL.RawQuery, http.StatusFound)
			return
		}
	} else if prompt == "consent" || !h.hasConsented(session.UserID, clientID, scope) {
		telemetry.Interaction("consent")
		consentURL := "/consent?" + r.URL.RawQuery
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	telemetry.Interaction("complete")
	h.issueAuthorizationResponse(w, r, client, session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource, organization, requestedActor, requestURI)
}

// ApplyRequestObject fills empty authorize fields from a signed request.
// The code challenge in that request wins over a query value.
func (h *Handler) ApplyRequestObject(params map[string]string) {
	defer telemetry.Step("oauth.Handler.ApplyRequestObject")()
	if h == nil || h.jarSvc == nil || strings.TrimSpace(params["request"]) == "" {
		return
	}
	client, _, _ := h.resolveClient(context.Background(), params["client_id"], params["redirect_uri"])
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

func (h *Handler) issueAuthorizationResponse(w http.ResponseWriter, r *http.Request, client *models.Client, session *Session, responseType, responseMode, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, resource, organization, requestedActor, requestURI string) {
	defer telemetry.Step("oauth.Handler.issueAuthorizationResponse")()
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
	if session != nil {
		scopes, err = h.narrowScopes(session.UserID, orgID, scopes)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to resolve scopes", state)
			return
		}
		scope = strings.Join(scopes, " ")
	}

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
		accessToken, err = h.issueAccessTokenFor(r.Context(), client.ID, session.UserID, scope, "Bearer", orgID, orgSlug, resource, "")
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

		h.stampCert(r, accessTok)
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
		idToken, err = h.oidcHandler.CreateIDToken(r.Context(), client.ID, session.UserID, nonce, scopes, oidc.IDTokenExtra{SID: session.ID, AuthTime: session.AuthTime, OrgID: orgID, OrgSlug: orgSlug, AccessToken: accessToken, Code: code})
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

	h.consumeRequestURI(requestURI)

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
		http.Redirect(w, r, withFragmentShield(redirectTo), http.StatusFound)
		return
	}

	if needsCode && !needsToken && !needsIDToken {
		// Code only - use query parameter. The fragment stops a browser from
		// reattaching an attacker-controlled fragment.
		redirectTo := redirectURI
		if strings.Contains(redirectTo, "?") {
			redirectTo += "&" + params.Encode()
		} else {
			redirectTo += "?" + params.Encode()
		}
		http.Redirect(w, r, withFragmentShield(redirectTo), http.StatusFound)
		return
	}

	// Implicit/hybrid - use fragment
	redirectTo := redirectURI + "#" + params.Encode()
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// failAuthorize redirects the error when the redirect URI is already known
// and registered. A missing, unknown, or out-of-band URI stays a JSON error.
func (h *Handler) failAuthorize(w http.ResponseWriter, r *http.Request, client *models.Client, redirectURI, responseType, responseMode, state, code, description string) {
	defer telemetry.Step("oauth.Handler.failAuthorize")()
	if client != nil && redirectURI != "" && !IsOutOfBandRedirect(redirectURI) && isValidRedirectURI(redirectURI, client.RedirectURIs) {
		sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, code, description, state)
		return
	}
	writeOAuthError(w, http.StatusBadRequest, code, description, state)
}

func firstOAuthParam(r *http.Request, key string) string {
	if values := r.URL.Query()[key]; len(values) > 0 && values[0] != "" {
		return values[0]
	}
	if r.PostForm != nil {
		if values := r.PostForm[key]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func withFragmentShield(raw string) string {
	if strings.Contains(raw, "#") {
		return raw
	}
	return raw + "#_"
}

// rejectDuplicateAuthorize refuses a repeated parameter. When the client and
// redirect URI are unambiguous, the browser is sent back to that URI so the
// client sees the error. Conflicting copies stay on a JSON error page.
func (h *Handler) rejectDuplicateAuthorize(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.rejectDuplicateAuthorize")()
	const desc = "Duplicate parameters are not allowed"
	clientID, clientOK := identicalFormValue(r, "client_id")
	redirectURI, redirectOK := identicalFormValue(r, "redirect_uri")
	requestURI, requestOK := identicalFormValue(r, "request_uri")
	if !clientOK || !redirectOK || !requestOK || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", desc, "")
		return
	}
	state, stateOK := identicalFormValue(r, "state")
	if !stateOK {
		state = ""
	}
	responseType, typeOK := identicalFormValue(r, "response_type")
	if !typeOK {
		responseType = ""
	}
	responseMode, modeOK := identicalFormValue(r, "response_mode")
	if !modeOK {
		responseMode = ""
	}
	if redirectURI == "" && requestURI != "" && h.parRepo != nil {
		par, err := h.parRepo.GetByRequestURI(requestURI)
		if err != nil || par == nil || par.ClientID != clientID || time.Now().After(par.ExpiresAt) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", desc, state)
			return
		}
		var params map[string]string
		if json.Unmarshal([]byte(par.RequestParams), &params) != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", desc, state)
			return
		}
		redirectURI = params["redirect_uri"]
		if responseType == "" {
			responseType = params["response_type"]
		}
		if responseMode == "" {
			responseMode = params["response_mode"]
		}
		if state == "" {
			state = params["state"]
		}
	}
	if redirectURI == "" || IsOutOfBandRedirect(redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", desc, state)
		return
	}
	client, code, _ := h.resolveClient(r.Context(), clientID, redirectURI)
	if code != "" || client == nil || !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", desc, state)
		return
	}
	sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "invalid_request", desc, state)
}

func identicalFormValue(r *http.Request, key string) (string, bool) {
	values := r.Form[key]
	if len(values) == 0 {
		return "", true
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return "", false
		}
	}
	return values[0], true
}

func sendOAuthRedirectError(w http.ResponseWriter, r *http.Request, redirectURI, responseType, responseMode, code, description, state string) {
	defer telemetry.Step("oauth.sendOAuthRedirectError")()
	params := url.Values{}
	params.Set("error", code)
	params.Set("error_description", description)
	if state != "" {
		params.Set("state", state)
	}
	if responseMode == "form_post" {
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
	if responseMode == "fragment" || (responseMode == "" && (responseHas(responseType, "token") || responseHas(responseType, "id_token"))) {
		http.Redirect(w, r, redirectURI+"#"+params.Encode(), http.StatusFound)
		return
	}
	separator := "?"
	if strings.Contains(redirectURI, "?") {
		separator = "&"
	}
	http.Redirect(w, r, withFragmentShield(redirectURI+separator+params.Encode()), http.StatusFound)
}

func (h *Handler) consumeRequestURI(requestURI string) {
	if h == nil || h.parRepo == nil || requestURI == "" {
		return
	}
	_ = h.parRepo.MarkUsed(requestURI)
}

func (h *Handler) redirectStoredRequestError(w http.ResponseWriter, r *http.Request, par *models.PushedAuthRequest, description string) {
	defer telemetry.Step("oauth.Handler.redirectStoredRequestError")()
	var params map[string]string
	if par == nil || json.Unmarshal([]byte(par.RequestParams), &params) != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", description, "")
		return
	}
	h.redirectRequestURIError(w, r, par.ClientID, params["redirect_uri"], params["response_type"], params["response_mode"], params["state"], description)
}

func (h *Handler) redirectUnknownRequestURI(w http.ResponseWriter, r *http.Request, clientID, description string) {
	defer telemetry.Step("oauth.Handler.redirectUnknownRequestURI")()
	if clientID == "" {
		clientID = firstOAuthParam(r, "client_id")
	}
	client, code, _ := h.resolveClient(r.Context(), clientID, "")
	if code != "" || client == nil || len(client.RedirectURIs) != 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", description, firstOAuthParam(r, "state"))
		return
	}
	h.redirectRequestURIError(w, r, clientID, client.RedirectURIs[0], "", "", firstOAuthParam(r, "state"), description)
}

func (h *Handler) redirectRequestURIError(w http.ResponseWriter, r *http.Request, clientID, redirectURI, responseType, responseMode, state, description string) {
	defer telemetry.Step("oauth.Handler.redirectRequestURIError")()
	client, code, _ := h.resolveClient(r.Context(), clientID, redirectURI)
	if code != "" || client == nil || redirectURI == "" || IsOutOfBandRedirect(redirectURI) || !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", description, state)
		return
	}
	sendOAuthRedirectError(w, r, redirectURI, responseType, responseMode, "invalid_request", description, state)
}
