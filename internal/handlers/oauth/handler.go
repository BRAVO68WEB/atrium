package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/branding"
	"github.com/bravo68web/oauth-impl/internal/cache"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

type Handler struct {
	clientRepo   *repository.ClientRepository
	userRepo     *repository.UserRepository
	tokenRepo    *repository.TokenRepository
	authCodeRepo *repository.AuthCodeRepository
	deviceRepo   *repository.DeviceCodeRepository
	cibaRepo     *repository.CIBARepository
	parRepo      *repository.PARRepository
	consentRepo  *repository.ConsentRepository
	dpopSvc      *service.DPoPService
	mtlsSvc      *service.MTLSService
	jarSvc       *service.JARService
	cfg          *config.Config
	q            queue.Queue
	oidcHandler  *oidc.Handler
	userSvc      *service.UserService
	sessions     *service.SessionService
	logout       *service.LogoutService
	logins       LoginRecorder
	pages        *template.Template
	hooks        *service.WebhookDispatcher
	brandTheme   branding.Theme
	audit        *service.AuditLog
	cimd         cache.Cache
	introspect   *service.Introspector
	orgs         *service.OrgService
	actorMu      sync.Mutex
	actorGrants  map[string]time.Time
	deviceLogin  DeviceLogin
}

// DeviceLogin binds a CIBA sign-in to a registered authenticator.
type DeviceLogin interface {
	PrepareLogin(userID, authReqID, interaction, binding string) (string, string, error)
	DeviceRevoked(authReqID string) bool
}

func (h *Handler) SetDeviceLogin(login DeviceLogin) {
	if h != nil {
		h.deviceLogin = login
	}
}

type LoginRecorder interface {
	Record(user *models.User, r *http.Request, success, mfa bool)
}

type Session struct {
	ID            string
	UserID        string
	Username      string
	Authenticated bool
	MFAVerified   bool
	AuthTime      time.Time
}

func NewHandler(
	clientRepo *repository.ClientRepository,
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	authCodeRepo *repository.AuthCodeRepository,
	deviceRepo *repository.DeviceCodeRepository,
	cibaRepo *repository.CIBARepository,
	parRepo *repository.PARRepository,
	consentRepo *repository.ConsentRepository,
	dpopSvc *service.DPoPService,
	mtlsSvc *service.MTLSService,
	jarSvc *service.JARService,
	cfg *config.Config,
	q queue.Queue,
	oidcHandler *oidc.Handler,
	userSvc *service.UserService,
	sessions *service.SessionService,
	logout *service.LogoutService,
	logins LoginRecorder,
) *Handler {
	return &Handler{
		clientRepo:   clientRepo,
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		authCodeRepo: authCodeRepo,
		deviceRepo:   deviceRepo,
		cibaRepo:     cibaRepo,
		parRepo:      parRepo,
		consentRepo:  consentRepo,
		dpopSvc:      dpopSvc,
		mtlsSvc:      mtlsSvc,
		jarSvc:       jarSvc,
		cfg:          cfg,
		q:            q,
		oidcHandler:  oidcHandler,
		userSvc:      userSvc,
		sessions:     sessions,
		logout:       logout,
		logins:       logins,
		brandTheme:   branding.Prepare(cfg),
		cimd:         cache.NewMemory(),
		introspect:   service.NewIntrospector(tokenRepo, userRepo, cfg),
	}
}

func (h *Handler) SetOrgs(orgs *service.OrgService) {
	if h != nil {
		h.orgs = orgs
	}
}

func (h *Handler) ClientName(id string) string {
	if h == nil || h.clientRepo == nil || id == "" {
		return ""
	}
	client, err := h.clientRepo.GetByID(id)
	if err != nil || client == nil {
		return ""
	}
	return client.Name
}

// ClientRedirectURIs returns the redirect URIs registered for a client.
func (h *Handler) ClientRedirectURIs(id string) []string {
	if h == nil || id == "" {
		return nil
	}
	client, code, _ := h.resolveClient(id, "")
	if code != "" || client == nil {
		return nil
	}
	out := make([]string, len(client.RedirectURIs))
	copy(out, client.RedirectURIs)
	return out
}

func (h *Handler) SetCache(c cache.Cache) {
	if h != nil && c != nil {
		h.cimd = c
	}
}

func (h *Handler) SetTemplates(t *template.Template) {
	h.pages = t
}

func (h *Handler) SetWebhooks(d *service.WebhookDispatcher) {
	h.hooks = d
}

var validResponseTypes = map[string]bool{
	"code":                true,
	"token":               true,
	"id_token":            true,
	"id_token token":      true,
	"code id_token":       true,
	"code token":          true,
	"code id_token token": true,
	"none":                true,
}

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

				// Merge JWT claims with query params (query params take precedence)
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
				if v, ok := claims["code_challenge"]; ok && codeChallenge == "" {
					codeChallenge = v
				}
				if v, ok := claims["code_challenge_method"]; ok && codeChallengeMethod == "" {
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
		if v, ok := params["code_challenge"]; ok && codeChallenge == "" {
			codeChallenge = v
		}
		if v, ok := params["code_challenge_method"]; ok && codeChallengeMethod == "" {
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
	needsCode := strings.Contains(responseType, "code")
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

	// Nonce is required for implicit/hybrid flows (response_type contains id_token)
	needsIDToken := strings.Contains(responseType, "id_token")
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

	needsCode := strings.Contains(responseType, "code")
	needsToken := strings.Contains(responseType, "token")
	needsIDToken := strings.Contains(responseType, "id_token")

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
		if len(params) > 0 {
			redirectTo := redirectURI
			if strings.Contains(redirectTo, "?") {
				redirectTo += "&" + params.Encode()
			} else {
				redirectTo += "?" + params.Encode()
			}
			http.Redirect(w, r, redirectTo, http.StatusFound)
		}
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

func (h *Handler) getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil || h.sessions == nil {
		return nil
	}
	stored, err := h.sessions.Get(cookie.Value)
	if err != nil || stored == nil {
		return nil
	}
	return &Session{
		ID:            stored.ID,
		UserID:        stored.UserID,
		Username:      stored.Username,
		Authenticated: true,
		MFAVerified:   stored.MFAVerified,
		AuthTime:      stored.AuthTime,
	}
}

func (h *Handler) GetSession(r *http.Request) *Session {
	return h.getSession(r)
}

func (h *Handler) SetSession(w http.ResponseWriter, userID, username string) {
	h.SetSessionWithMFA(w, userID, username, true)
}

func (h *Handler) SetSessionWithMFA(w http.ResponseWriter, userID, username string, mfaVerified bool) {
	h.SetSessionRequest(w, nil, userID, username, mfaVerified)
}

func (h *Handler) SetSessionRequest(w http.ResponseWriter, r *http.Request, userID, username string, mfaVerified bool) {
	if h.sessions == nil {
		return
	}
	ua, ip := "", ""
	if r != nil {
		ua = r.UserAgent()
		trusted := []string(nil)
		if h.cfg != nil {
			trusted = h.cfg.Security.TrustedProxies
		}
		ip = service.ClientIP(r, trusted)
	}
	sess, err := h.sessions.Start(userID, username, ua, ip, mfaVerified)
	if err != nil {
		return
	}
	h.writeSessionCookie(w, sess.ID)
}

func (h *Handler) MarkSessionMFA(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil || h.sessions == nil {
		return
	}
	_ = h.sessions.MarkMFA(cookie.Value)
	h.writeSessionCookie(w, cookie.Value)
}

func (h *Handler) writeSessionCookie(w http.ResponseWriter, sessionID string) {
	maxAge := int(h.cfg.Security.SessionLifetime.Seconds())
	if maxAge <= 0 {
		maxAge = 8 * 3600
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.TLS.Enabled,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (h *Handler) hasConsented(userID, clientID, scope string) bool {
	consent, err := h.consentRepo.Get(userID, clientID)
	if err != nil {
		return false
	}
	requestedScopes := crypto.NormalizeScopes(scope)
	for _, s := range requestedScopes {
		if !containsScope(consent.Scopes, s) {
			return false
		}
	}
	return true
}

func (h *Handler) clearSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return
	}
	if h.logout != nil {
		h.logout.End(cookie.Value)
	} else if h.sessions != nil {
		_ = h.sessions.Revoke(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.TLS.Enabled,
		MaxAge:   -1,
	})
}

func (h *Handler) ClearSession(w http.ResponseWriter, r *http.Request) {
	h.clearSession(w, r)
}

func (h *Handler) GetPARParams(requestURI string) (map[string]string, error) {
	par, err := h.parRepo.GetByRequestURI(requestURI)
	if err != nil {
		return nil, err
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(par.RequestParams), &params); err != nil {
		return nil, err
	}
	return params, nil
}

// SaveConsent persists the user's consent for a client
func (h *Handler) SaveConsent(userID, clientID string, scopes []string) error {
	return h.consentRepo.Save(userID, clientID, scopes)
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	// Check for duplicate parameters
	if hasDuplicateParams(r) {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Duplicate parameters are not allowed")
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeToken(w, r)
	case "client_credentials":
		h.handleClientCredentialsToken(w, r)
	case "refresh_token":
		h.handleRefreshToken(w, r)
	case "password":
		h.handlePasswordToken(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.HandleDeviceToken(w, r)
	case "urn:openid:params:grant-type:ciba":
		h.HandleCIBAToken(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		h.handleTokenExchange(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type: "+grantType)
	}
}

func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	token := r.Form.Get("token")
	tokenTypeHint := r.Form.Get("token_type_hint")

	if token == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	clientID, clientSecret := presentedClient(r)

	// Require client authentication
	if clientID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client authentication required")
		return
	}

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
		return
	}

	if authenticateClient(client, clientID, clientSecret, false) != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	if !h.revokeDPoP(w, r, client, token) {
		return
	}

	switch tokenTypeHint {
	case "refresh_token":
		if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil {
			// Validate client binding
			if rt.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeRefreshToken(token)
			if rt.AccessToken != "" {
				_ = h.tokenRepo.RevokeAccessToken(rt.AccessToken)
			}
		}
	case "access_token":
		if at, err := h.tokenRepo.GetAccessToken(token); err == nil {
			// Validate client binding
			if at.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeAccessToken(token)
			// Cascade: also revoke associated refresh token
			if rt, err := h.tokenRepo.GetRefreshTokenByAccessToken(token); err == nil {
				_ = h.tokenRepo.RevokeRefreshToken(rt.Token)
			}
		}
	default:
		if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil {
			if rt.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeRefreshToken(token)
			if rt.AccessToken != "" {
				_ = h.tokenRepo.RevokeAccessToken(rt.AccessToken)
			}
		} else if at, err := h.tokenRepo.GetAccessToken(token); err == nil {
			if at.ClientID != clientID {
				writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Token does not belong to this client")
				return
			}
			_ = h.tokenRepo.RevokeAccessToken(token)
			// Cascade: also revoke associated refresh token
			if rt, err := h.tokenRepo.GetRefreshTokenByAccessToken(token); err == nil {
				_ = h.tokenRepo.RevokeRefreshToken(rt.Token)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	clientID, clientSecret := presentedClient(r)
	client, err := h.clientRepo.GetByID(clientID)
	if err != nil || client == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if authenticateClient(client, clientID, clientSecret, false) != "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	result, err := h.introspect.Introspect(client, r.Form.Get("token"), r.Form.Get("token_type_hint"))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if result != nil && result.Active && result.Sub != "" && h.oidcHandler != nil {
		computed, err := h.oidcHandler.SubjectFor(result.ClientID, result.Sub)
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to resolve subject")
			return
		}
		result.Sub = computed
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if h.cfg != nil && !h.cfg.Registration.DCREnabled {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "registration_disabled",
			"error_description": "Dynamic client registration is disabled",
		})
		return
	}

	var req struct {
		RedirectURIs                          []string `json:"redirect_uris"`
		TokenEndpointAuthMethod               string   `json:"token_endpoint_auth_method"`
		GrantTypes                            []string `json:"grant_types"`
		ResponseTypes                         []string `json:"response_types"`
		ClientName                            string   `json:"client_name"`
		Scope                                 string   `json:"scope"`
		DPoPBoundAccessTokens                 bool     `json:"dpop_bound_access_tokens"`
		RequirePushedAuthorizationRequests    bool     `json:"require_pushed_authorization_requests"`
		BackchannelTokenDeliveryMode          string   `json:"backchannel_token_delivery_mode"`
		BackchannelClientNotificationEndpoint string   `json:"backchannel_client_notification_endpoint"`
		BackchannelLogoutURI                  string   `json:"backchannel_logout_uri"`
		BackchannelLogoutSessionRequired      *bool    `json:"backchannel_logout_session_required"`
		PostLogoutRedirectURIs                []string `json:"post_logout_redirect_uris"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "Invalid request body"})
		return
	}

	if req.ClientName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "client_name is required"})
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "redirect_uris is required"})
		return
	}

	for _, uri := range req.RedirectURIs {
		if !isValidURI(uri) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "Invalid redirect URI: " + uri})
			return
		}
	}

	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}

	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}

	client := &models.Client{
		ID:                                    uuid.New().String(),
		Secret:                                mustGenerateToken(),
		Name:                                  req.ClientName,
		RedirectURIs:                          req.RedirectURIs,
		GrantTypes:                            req.GrantTypes,
		Scopes:                                service.StripManagement(strings.Fields(req.Scope)),
		TokenEndpointAuthMethod:               req.TokenEndpointAuthMethod,
		DPoPBoundAccessTokens:                 req.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests:    req.RequirePushedAuthorizationRequests,
		BackchannelTokenDeliveryMode:          req.BackchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: req.BackchannelClientNotificationEndpoint,
		BackchannelLogoutURI:                  req.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:      req.BackchannelLogoutSessionRequired == nil || *req.BackchannelLogoutSessionRequired,
		PostLogoutRedirectURIs:                req.PostLogoutRedirectURIs,
		RegistrationSource:                    "dcr",
		DCREnabled:                            true,
		CreatedAt:                             time.Now(),
		UpdatedAt:                             time.Now(),
	}

	if err := h.clientRepo.Create(client); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "Failed to create client"})
		return
	}
	if h.audit != nil {
		h.audit.Write("client", client.ID, "client.register", "client", client.ID, r, map[string]any{"name": client.Name, "source": "dcr"})
	}

	response := map[string]interface{}{
		"client_id":                  client.ID,
		"client_secret":              client.Secret,
		"client_id_issued_at":        client.CreatedAt.Unix(),
		"client_secret_expires_at":   0,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             req.ResponseTypes,
		"client_name":                client.Name,
		"scope":                      strings.Join(client.Scopes, " "),
	}

	writeJSON(w, http.StatusCreated, response)
}

func isValidRedirectURI(uri string, allowedURIs []string) bool {
	if len(allowedURIs) == 0 {
		return isValidURI(uri)
	}
	for _, allowed := range allowedURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func isValidURI(uri string) bool {
	return IsOutOfBandRedirect(uri) || strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "http://localhost")
}

func (h *Handler) issueAccessToken(clientID, userID, scope, tokenType string) (string, error) {
	return h.issueAccessTokenFor(clientID, userID, scope, tokenType, "", "", "", "")
}

func (h *Handler) issueAccessTokenFor(clientID, userID, scope, tokenType, orgID, orgSlug, resource, actor string) (string, error) {
	format := ""
	var lifetime time.Duration
	if h.cfg != nil {
		format = h.cfg.Security.AccessTokenFormat
		lifetime = h.cfg.Security.AccessTokenLifetime
	}
	if format == "jwt" || actor != "" {
		if h.oidcHandler == nil {
			return "", fmt.Errorf("jwt access tokens require the oidc handler")
		}
		return h.oidcHandler.CreateAccessTokenJWT(clientID, userID, scope, tokenType, lifetime, orgID, orgSlug, resource, actor)
	}
	return crypto.GenerateToken()
}

func actorGrantKey(sessionID, clientID, actor string) string {
	return sessionID + "\n" + clientID + "\n" + actor
}

// GrantActorConsent remembers that this browser session just approved an actor.
func (h *Handler) GrantActorConsent(sessionID, clientID, actor string) {
	if h == nil || sessionID == "" || clientID == "" || actor == "" {
		return
	}
	h.actorMu.Lock()
	defer h.actorMu.Unlock()
	if h.actorGrants == nil {
		h.actorGrants = map[string]time.Time{}
	}
	h.actorGrants[actorGrantKey(sessionID, clientID, actor)] = time.Now().Add(2 * time.Minute)
}

func (h *Handler) takeActorConsent(sessionID, clientID, actor string) bool {
	if h == nil || sessionID == "" {
		return false
	}
	h.actorMu.Lock()
	defer h.actorMu.Unlock()
	if h.actorGrants == nil {
		return false
	}
	key := actorGrantKey(sessionID, clientID, actor)
	expires, ok := h.actorGrants[key]
	delete(h.actorGrants, key)
	return ok && time.Now().Before(expires)
}

// actorSubject returns the subject of an access token issued by this server.
// A token with no user names its client. A JWT must also verify.
func (h *Handler) actorSubject(raw string) (string, error) {
	if h == nil || h.tokenRepo == nil || strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("invalid actor token")
	}
	at, err := h.tokenRepo.GetAccessToken(raw)
	if err != nil || at == nil || at.Revoked || (!at.ExpiresAt.IsZero() && time.Now().After(at.ExpiresAt)) {
		return "", fmt.Errorf("invalid actor token")
	}
	subject := at.ClientID
	if at.UserID != "" {
		subject = at.UserID
	}
	if strings.Count(raw, ".") == 2 {
		if h.oidcHandler == nil {
			return "", fmt.Errorf("invalid actor token")
		}
		sub, err := h.oidcHandler.AccessTokenSubject(raw)
		if err != nil {
			return "", fmt.Errorf("invalid actor token")
		}
		subject = sub
	}
	if subject == "" {
		return "", fmt.Errorf("invalid actor token")
	}
	return subject, nil
}

func (h *Handler) needsOrgChoice(client *models.Client, userID, requested string) (bool, error) {
	if h == nil || h.orgs == nil {
		return false, nil
	}
	return h.orgs.NeedsChoice(client, userID, requested)
}

// NeedsOrgChoice reports whether /organization should be shown for this
// authorize request. clientID is loaded when it names a real client.
func (h *Handler) NeedsOrgChoice(clientID, userID, requested string) (bool, error) {
	var client *models.Client
	if h != nil && clientID != "" {
		if loaded, code, _ := h.resolveClient(clientID, ""); code == "" {
			client = loaded
		}
	}
	return h.needsOrgChoice(client, userID, requested)
}

func (h *Handler) UserOrgs(userID string) ([]*models.Organization, error) {
	if h == nil || h.orgs == nil {
		return nil, nil
	}
	return h.orgs.ListForUser(userID)
}

func (h *Handler) orgSlug(orgID string) string {
	if h == nil || h.orgs == nil || orgID == "" {
		return ""
	}
	org, err := h.orgs.Get(orgID)
	if err != nil || org == nil {
		return ""
	}
	return org.Slug
}

func (h *Handler) applyOrg(client *models.Client, user *models.User, requested string) (string, string, string, string) {
	if h == nil || h.orgs == nil {
		if strings.TrimSpace(requested) != "" {
			return "", "", "invalid_request", "organizations are disabled"
		}
		return "", "", "", ""
	}
	choice, err := h.orgs.Resolve(client, user, requested)
	if err == nil && choice == nil {
		return "", "", "", ""
	}
	if err == nil {
		return choice.ID, choice.Slug, "", ""
	}
	switch {
	case errors.Is(err, service.ErrOrgDisabled), errors.Is(err, service.ErrOrgInvalid):
		return "", "", "invalid_request", err.Error()
	case errors.Is(err, service.ErrOrgDenied):
		return "", "", "access_denied", err.Error()
	default:
		return "", "", "server_error", "failed to resolve organization"
	}
}

func mustGenerateToken() string {
	token, err := crypto.GenerateToken()
	if err != nil {
		return uuid.New().String()
	}
	return token
}

func hasDuplicateParams(r *http.Request) bool {
	// Check URL query parameters
	urlValues := r.URL.Query()
	for key := range urlValues {
		if len(urlValues[key]) > 1 {
			return true
		}
	}

	// Check form parameters (POST body)
	if r.Form != nil {
		for key := range r.Form {
			if len(r.Form[key]) > 1 {
				return true
			}
		}
	}

	return false
}

func writeOAuthError(w http.ResponseWriter, status int, code, description, state string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response := map[string]string{
		"error":             code,
		"error_description": description,
	}
	if state != "" {
		response["state"] = state
	}
	_ = json.NewEncoder(w).Encode(response)
}

func writeTokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeTokenResponse(w http.ResponseWriter, accessToken, refreshToken string, expiresIn int, tokenType, scope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}

	if refreshToken != "" {
		response["refresh_token"] = refreshToken
	}

	if scope != "" {
		response["scope"] = scope
	}

	_ = json.NewEncoder(w).Encode(response)
}

func writeOIDCTokenResponse(w http.ResponseWriter, accessToken, refreshToken, idToken string, expiresIn int, tokenType, scope string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}

	if refreshToken != "" {
		response["refresh_token"] = refreshToken
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	if scope != "" {
		response["scope"] = scope
	}

	_ = json.NewEncoder(w).Encode(response)
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
