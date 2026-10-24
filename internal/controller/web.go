package controller

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/oauth-impl/internal/branding"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/push"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type WebController struct {
	userSvc      *service.UserService
	totpSvc      *service.TOTPService
	account      *service.AccountService
	cfg          *config.Config
	oauthHandler *oauth.Handler
	templates    *template.Template
	theme        branding.Theme
	social       *service.SocialService
	audit        *service.AuditLog
	push         *push.Handler
}

func (c *WebController) SetPush(h *push.Handler) {
	defer telemetry.Step("controller.WebController.SetPush")()
	if c != nil {
		c.push = h
	}
}

func (c *WebController) SetAudit(a *service.AuditLog) {
	defer telemetry.Step("controller.WebController.SetAudit")()
	if c != nil {
		c.audit = a
	}
}

func (c *WebController) Templates() *template.Template {
	defer telemetry.Step("controller.WebController.Templates")()
	return c.templates
}

func ParseTemplates(templateFS embed.FS, overlayDir string) (*template.Template, error) {
	defer telemetry.Step("controller.ParseTemplates")()
	funcMap := template.FuncMap{
		"split": strings.Split,
		"scopeLabel": func(scope string) string {
			switch scope {
			case "openid":
				return "Sign you in"
			case "profile":
				return "Read your profile"
			case "email":
				return "Read your email address"
			case "offline_access":
				return "Stay signed in"
			default:
				return scope
			}
		},
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "internal/templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}
	if overlayDir == "" {
		return tmpl, nil
	}
	info, err := os.Stat(overlayDir)
	if err != nil {
		return nil, fmt.Errorf("branding templates: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("branding templates: %s is not a directory", overlayDir)
	}
	matches, err := filepath.Glob(filepath.Join(overlayDir, "*.html"))
	if err != nil {
		return nil, fmt.Errorf("branding templates: %w", err)
	}
	for _, name := range matches {
		body, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("branding templates: %w", err)
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("branding templates: %s is empty", name)
		}
	}
	if len(matches) == 0 {
		return tmpl, nil
	}
	if _, err := tmpl.ParseFiles(matches...); err != nil {
		return nil, fmt.Errorf("branding templates: %w", err)
	}
	return tmpl, nil
}

func NewWebController(userSvc *service.UserService, totpSvc *service.TOTPService, account *service.AccountService, cfg *config.Config, templateFS embed.FS, oauthHandler *oauth.Handler) (*WebController, error) {
	defer telemetry.Step("controller.NewWebController")()
	overlay := ""
	if cfg != nil {
		overlay = cfg.Branding.Templates
	}
	tmpl, err := ParseTemplates(templateFS, overlay)
	if err != nil {
		return nil, err
	}

	return &WebController{
		userSvc:      userSvc,
		totpSvc:      totpSvc,
		account:      account,
		cfg:          cfg,
		oauthHandler: oauthHandler,
		templates:    tmpl,
		theme:        branding.Prepare(cfg),
	}, nil
}

func (c *WebController) SetSocial(s *service.SocialService) {
	defer telemetry.Step("controller.WebController.SetSocial")()
	if c != nil {
		c.social = s
	}
}

func (c *WebController) ServeBrandAsset(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.ServeBrandAsset")()
	branding.AssetHandler(c.cfg).ServeHTTP(w, r)
}

func (c *WebController) renderPage(w http.ResponseWriter, r *http.Request, page, pageTitle, heading string, params map[string]string, extra map[string]any) {
	defer telemetry.Step("controller.WebController.renderPage")()
	if extra == nil {
		extra = map[string]any{}
	}
	secure := c != nil && c.cfg != nil && c.cfg.Server.TLS.Enabled
	extra["CSRFToken"] = issueCSRF(w, r, secure)
	if c != nil && c.cfg != nil {
		extra["BotProvider"] = c.cfg.Security.BotProtection.Provider
		extra["BotSiteKey"] = c.cfg.Security.BotProtection.SiteKey
	}
	if page == "login.html" {
		heading = c.theme.LoginTitle()
	}
	data := oauthTemplateData(params, extra)
	clientName := ""
	if c.oauthHandler != nil {
		clientName = c.oauthHandler.ClientName(params["client_id"])
	}
	c.theme.Apply(data, pageTitle, heading, clientName)
	if c.social != nil {
		data["Providers"] = c.social.Buttons()
	}
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	data["OAuthQuery"] = q.Encode()
	if c.templates == nil {
		http.Error(w, "template unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.templates.ExecuteTemplate(w, page, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func (c *WebController) getSession(r *http.Request) *oauth.Session {
	defer telemetry.Step("controller.WebController.getSession")(

	// buildAuthorizeURL constructs /oauth/authorize URL with all OAuth params
	)
	return c.oauthHandler.GetSession(r)
}

func (c *WebController) redirectAfterLogin(w http.ResponseWriter, r *http.Request, params map[string]string) {
	defer telemetry.Step("controller.WebController.redirectAfterLogin")()
	next := SafeNext(params["next"])
	if isLocalURL(next) {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	http.Redirect(w, r, c.buildAuthorizeURL(params), http.StatusFound)
}

func (c *WebController) clientRedirects(clientID string) []string {
	defer telemetry.Step("controller.WebController.clientRedirects")()
	if c == nil || c.oauthHandler == nil {
		return nil
	}
	return c.oauthHandler.ClientRedirectURIs(clientID)
}

// isValidRedirectURL reports whether a redirect target is https, or http on localhost.
func isValidRedirectURL(raw string) bool {
	defer telemetry.Step("controller.isValidRedirectURL")()
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	switch parsed.Scheme {
	case "https":
		return parsed.Hostname() != ""
	case "http":
		host := parsed.Hostname()
		return host == "localhost" || host == "127.0.0.1"
	default:
		return false
	}
}

// isValidRedirectURI reports whether uri is one of the client's registered redirect URIs.
func isValidRedirectURI(uri string, allowed []string) bool {
	defer telemetry.Step("controller.isValidRedirectURI")()
	if uri == "" || strings.ContainsAny(uri, "\r\n\\") {
		return false
	}
	for _, item := range allowed {
		if item == uri {
			return true
		}
	}
	return false
}

// isLocalURL allows only the same-origin paths SafeNext returns.
func isLocalURL(raw string) bool {
	defer telemetry.Step("controller.isLocalURL")()
	if raw == "" || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return false
	}
	return parsed.Path == "/device" || parsed.Path == "/oauth/authorize" || parsed.Path == "/push/enroll" || parsed.Path == "/push/approve" || parsed.Path == "/profile"
}

func (c *WebController) buildAuthorizeURL(params map[string]string) string {
	defer telemetry.Step("controller.WebController.buildAuthorizeURL")()
	parts := []string{}
	for k, v := range params {
		if v != "" && k != "next" {
			parts = append(parts, k+"="+url.QueryEscape(v))
		}
	}
	return "/oauth/authorize?" + strings.Join(parts, "&")
}

// extractOAuthParams extracts OAuth params from request
func extractOAuthParams(r *http.Request) map[string]string {
	defer telemetry.Step("controller.extractOAuthParams")()
	return map[string]string{
		"client_id":             r.URL.Query().Get("client_id"),
		"redirect_uri":          r.URL.Query().Get("redirect_uri"),
		"response_type":         r.URL.Query().Get("response_type"),
		"scope":                 r.URL.Query().Get("scope"),
		"state":                 r.URL.Query().Get("state"),
		"nonce":                 r.URL.Query().Get("nonce"),
		"code_challenge":        r.URL.Query().Get("code_challenge"),
		"code_challenge_method": r.URL.Query().Get("code_challenge_method"),
		"request_uri":           r.URL.Query().Get("request_uri"),
		"prompt":                r.URL.Query().Get("prompt"),
		"login_hint":            r.URL.Query().Get("login_hint"),
		"resource":              r.URL.Query().Get("resource"),
		"response_mode":         r.URL.Query().Get("response_mode"),
		"request":               r.URL.Query().Get("request"),
		"organization":          r.URL.Query().Get("organization"),
		"requested_actor":       r.URL.Query().Get("requested_actor"),
		"next":                  r.URL.Query().Get("next"),
	}
}

// extractOAuthParamsFromForm extracts OAuth params from POST form
func extractOAuthParamsFromForm(r *http.Request) map[string]string {
	defer telemetry.Step("controller.extractOAuthParamsFromForm")()
	return map[string]string{
		"client_id":             r.FormValue("client_id"),
		"redirect_uri":          r.FormValue("redirect_uri"),
		"response_type":         r.FormValue("response_type"),
		"scope":                 r.FormValue("scope"),
		"state":                 r.FormValue("state"),
		"nonce":                 r.FormValue("nonce"),
		"code_challenge":        r.FormValue("code_challenge"),
		"code_challenge_method": r.FormValue("code_challenge_method"),
		"request_uri":           r.FormValue("request_uri"),
		"prompt":                r.FormValue("prompt"),
		"login_hint":            r.FormValue("login_hint"),
		"resource":              r.FormValue("resource"),
		"response_mode":         r.FormValue("response_mode"),
		"request":               r.FormValue("request"),
		"organization":          r.FormValue("organization"),
		"requested_actor":       r.FormValue("requested_actor"),
		"next":                  r.FormValue("next"),
	}
}

// oauthTemplateData creates template data with OAuth params
func oauthTemplateData(params map[string]string, extra map[string]interface{}) map[string]interface{} {
	defer telemetry.Step("controller.oauthTemplateData")()
	data := map[string]interface{}{
		"ClientID":            params["client_id"],
		"RedirectURI":         params["redirect_uri"],
		"ResponseType":        params["response_type"],
		"Scope":               params["scope"],
		"State":               params["state"],
		"Nonce":               params["nonce"],
		"CodeChallenge":       params["code_challenge"],
		"CodeChallengeMethod": params["code_challenge_method"],
		"RequestURI":          params["request_uri"],
		"Prompt":              params["prompt"],
		"LoginHint":           params["login_hint"],
		"Resource":            params["resource"],
		"ResponseMode":        params["response_mode"],
		"Request":             params["request"],
		"Organization":        params["organization"],
		"RequestedActor":      params["requested_actor"],
		"Next":                params["next"],
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// ──────────────────────────────────────────────
// Login Flow
// ──────────────────────────────────────────────

func (c *WebController) HandlePushEnroll(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandlePushEnroll")()
	if c == nil || c.push == nil {
		http.NotFound(w, r)
		return
	}
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		next := "/push/enroll"
		if r.URL.RawQuery != "" {
			next += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	item, ok := c.push.Enroll(w, r)
	if !ok {
		return
	}
	c.renderPage(w, r, "push_enroll.html", "Register a device", "Register a device", map[string]string{}, map[string]any{
		"QRCodeBase64":      item.QR,
		"EnrollURL":         item.URL,
		"RegistrationToken": item.Token,
	})
}

func (c *WebController) HandlePushApprove(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandlePushApprove")()
	if c == nil || c.push == nil {
		http.NotFound(w, r)
		return
	}
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/push/approve"), http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if !csrfOK(r) {
			rejectCSRF(w)
			return
		}
		approve := r.Form.Get("action") != "deny"
		status := "denied"
		if approve {
			status = "approved"
		}
		if err := c.push.Service().FinishLogin(session.UserID, r.Form.Get("auth_req_id"), status, r.Form.Get("proof")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := c.oauthHandler.CompleteCIBA(r.Form.Get("auth_req_id"), session.UserID, approve); err != nil {
			http.Error(w, "sign-in request is not pending", http.StatusBadRequest)
			return
		}
		c.renderPage(w, r, "push_approve.html", "Sign-in", "Sign-in", map[string]string{}, map[string]any{
			"Approved": approve,
			"Pending":  false,
		})
		return
	}
	pending, err := c.push.Service().PendingLogins(session.UserID)
	if err != nil || len(pending) == 0 {
		c.renderPage(w, r, "push_approve.html", "Sign-in", "Sign-in", map[string]string{}, map[string]any{
			"Pending": false,
		})
		return
	}
	item := pending[0]
	extra := map[string]any{
		"Pending":         true,
		"AuthReqID":       item.AuthReqID,
		"InteractionType": item.InteractionType,
	}
	switch item.InteractionType {
	case "number_choose":
		extra["Choices"] = push.NumberChoices(item.BindingMessage)
	case "input_manual":
	default:
		extra["BindingMessage"] = item.BindingMessage
	}
	c.renderPage(w, r, "push_approve.html", "Sign-in", "Approve sign-in", map[string]string{}, extra)
}

func (c *WebController) HandleLoginPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleLoginPage")()
	params := extractOAuthParams(r)
	c.renderPage(w, r, "login.html", "Login", "Sign In", params, map[string]any{
		"Error":     "",
		"LoginHint": params["login_hint"],
	})
}

func (c *WebController) HandleLogin(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleLogin")()
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	params := extractOAuthParamsFromForm(r)
	if !c.botOK(w, r, username) {
		return
	}

	user, err := c.userSvc.Authenticate(username, password)
	if err != nil {
		if existing, lookupErr := c.userSvc.FindByLogin(username); lookupErr == nil && c.account != nil {
			c.account.Record(existing, r, false, false)
		}
		c.renderPage(w, r, "login.html", "Login", "Sign In", params, map[string]any{
			"Error": "Invalid credentials",
		})
		return
	}

	c.finishLogin(w, r, user, params)
}

func (c *WebController) finishLogin(w http.ResponseWriter, r *http.Request, user *models.User, params map[string]string) {
	defer telemetry.Step("controller.WebController.finishLogin")()
	if c.cfg != nil && c.cfg.Security.MFA.Required && c.totpSvc != nil {
		mfaEnabled, _ := c.totpSvc.IsMFAEnabled(user.ID)
		c.oauthHandler.SetSessionRequest(w, r, user.ID, user.Username, false)
		if !mfaEnabled {
			http.Redirect(w, r, "/mfa/enroll?"+paramsQuery(params), http.StatusFound)
			return
		}
		c.renderPage(w, r, "mfa.html", "Two-Factor Authentication", "Two-Factor Authentication", params, map[string]any{
			"Error": "",
		})
		return
	}
	if c.account != nil {
		c.account.Record(user, r, true, false)
	}
	if c.oauthHandler != nil {
		c.oauthHandler.SetSessionRequest(w, r, user.ID, user.Username, true)
	}
	c.redirectAfterLogin(w, r, params)
}

func (c *WebController) botOK(w http.ResponseWriter, r *http.Request, username string) bool {
	defer telemetry.Step("controller.WebController.botOK")()
	if c == nil || c.cfg == nil || c.cfg.Security.BotProtection.Provider == "" {
		return true
	}
	if err := service.VerifyBot(r.Context(), c.cfg.Security.BotProtection, r.FormValue("bot_token"), r.RemoteAddr); err != nil {
		if username != "" && c.userSvc != nil {
			if existing, lookupErr := c.userSvc.FindByLogin(username); lookupErr == nil && c.account != nil {
				c.account.Record(existing, r, false, false)
			}
		}
		if c.audit != nil {
			c.audit.Write("user", username, "bot.failure", "login", username, r, map[string]any{"provider": c.cfg.Security.BotProtection.Provider})
		}
		writeError(w, http.StatusBadRequest, "bot_failed", "Bot verification failed")
		return false
	}
	return true
}

func paramsQuery(params map[string]string) string {
	defer telemetry.Step("controller.paramsQuery")()
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

func (c *WebController) HandleSocialStart(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleSocialStart")()
	if c.social == nil {
		http.NotFound(w, r)
		return
	}
	authURL, err := c.social.Begin(r.Context(), chi.URLParam(r, "provider"), extractOAuthParams(r))
	if errors.Is(err, service.ErrSocialProviderNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		c.renderPage(w, r, "login.html", "Login", "Sign In", extractOAuthParams(r), map[string]any{
			"Error": "The identity provider is unavailable.",
		})
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (c *WebController) HandleSocialCallback(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleSocialCallback")()
	if c.social == nil {
		http.NotFound(w, r)
		return
	}
	id := chi.URLParam(r, "provider")
	result, err := c.social.Complete(r.Context(), id, r.URL.Query().Get("code"), r.URL.Query().Get("state"))
	params := result.Params
	if params == nil {
		params = map[string]string{}
	}
	switch {
	case errors.Is(err, service.ErrSocialProviderNotFound):
		http.NotFound(w, r)
	case errors.Is(err, service.ErrSocialRegistrationDisabled):
		writeHTMLStatus(w, http.StatusForbidden, "Social registration is disabled", "Social registration is disabled. Sign in with an existing account.")
	case errors.Is(err, service.ErrSocialEmailInUse):
		c.renderPage(w, r, "login.html", "Login", "Sign In", params, map[string]any{
			"Error": "An account with this email already exists. Sign in with your password.",
		})
	case errors.Is(err, service.ErrSocialAccountDisabled):
		c.renderPage(w, r, "login.html", "Login", "Sign In", params, map[string]any{
			"Error": "Invalid credentials",
		})
	case errors.Is(err, service.ErrSocialState):
		c.renderPage(w, r, "login.html", "Login", "Sign In", params, map[string]any{
			"Error": "Sign-in could not be completed. Try again.",
		})
	case err != nil:
		c.renderPage(w, r, "login.html", "Login", "Sign In", params, map[string]any{
			"Error": "The identity provider rejected the sign-in.",
		})
	default:
		c.finishLogin(w, r, result.User, params)
	}
}

func writeHTMLStatus(w http.ResponseWriter, status int, title, message string) {
	defer telemetry.Step("controller.writeHTMLStatus")()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title></head><body><h1>%s</h1><p>%s</p><p><a href=\"/login\">Sign in</a></p></body></html>", title, title, message)
}

// ──────────────────────────────────────────────
// MFA Verification Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleMFA(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleMFA")()
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	code := r.FormValue("code")
	params := extractOAuthParamsFromForm(r)

	session := c.getSession(r)
	if session == nil {
		http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
		return
	}

	valid, err := c.totpSvc.VerifyLogin(session.UserID, code)
	if err != nil || !valid {
		if user, lookupErr := c.userSvc.GetUser(session.UserID); lookupErr == nil && c.account != nil {
			c.account.Record(user, r, false, true)
		}
		c.renderPage(w, r, "mfa.html", "Two-Factor Authentication", "Two-Factor Authentication", params, map[string]any{
			"Error": "Invalid TOTP code",
		})
		return
	}

	c.oauthHandler.MarkSessionMFA(w, r)
	if user, lookupErr := c.userSvc.GetUser(session.UserID); lookupErr == nil && c.account != nil {
		c.account.Record(user, r, true, true)
	}
	c.redirectAfterLogin(w, r, params)
}

// ──────────────────────────────────────────────
// MFA Enrollment Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleMFAEnrollPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleMFAEnrollPage")()
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	params := extractOAuthParams(r)

	result, err := c.totpSvc.EnableMFA(session.UserID, session.Username)
	if err != nil {
		c.renderPage(w, r, "mfa_enroll.html", "Setup Two-Factor Authentication", "Setup Two-Factor Authentication", params, map[string]any{
			"Error": "Failed to generate MFA enrollment",
		})
		return
	}

	c.renderPage(w, r, "mfa_enroll.html", "Setup Two-Factor Authentication", "Setup Two-Factor Authentication", params, map[string]any{
		"QRCodeBase64": result.QRBase64,
		"Secret":       result.Secret,
		"Issuer":       c.cfg.Security.MFA.Issuer,
		"Username":     session.Username,
		"Error":        "",
	})
}

func (c *WebController) HandleMFAEnrollVerify(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleMFAEnrollVerify")()
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	code := r.FormValue("code")
	secret := r.FormValue("secret")
	params := extractOAuthParamsFromForm(r)

	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
		return
	}

	if err := c.totpSvc.ConfirmMFA(session.UserID, code); err != nil {
		result, enrollErr := c.totpSvc.EnableMFA(session.UserID, session.Username)
		shown := secret
		qr := ""
		if enrollErr == nil && result != nil {
			shown = result.Secret
			qr = result.QRBase64
		}
		c.renderPage(w, r, "mfa_enroll.html", "Setup Two-Factor Authentication", "Setup Two-Factor Authentication", params, map[string]any{
			"QRCodeBase64": qr,
			"Secret":       shown,
			"Issuer":       c.cfg.Security.MFA.Issuer,
			"Username":     session.Username,
			"Error":        "Invalid code. Please try again.",
		})
		return
	}

	c.oauthHandler.MarkSessionMFA(w, r)
	c.redirectAfterLogin(w, r, params)
}

// ──────────────────────────────────────────────
// Registration Flow
// ──────────────────────────────────────────────

func (c *WebController) registrationDisabled() bool {
	defer telemetry.Step("controller.WebController.registrationDisabled")()
	return c != nil && c.cfg != nil && c.cfg.Security.DisableRegistration
}

func writeRegistrationDisabled(w http.ResponseWriter) {
	defer telemetry.Step("controller.writeRegistrationDisabled")()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Registration disabled</title></head><body><h1>Registration is disabled</h1><p><a href="/login">Sign in</a></p></body></html>`))
}

func (c *WebController) HandleRegisterPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleRegisterPage")()
	if c.registrationDisabled() {
		writeRegistrationDisabled(w)
		return
	}
	params := extractOAuthParams(r)
	c.renderPage(w, r, "register.html", "Register", "Create Account", params, map[string]any{
		"Error": "",
	})
}

func (c *WebController) HandleRegister(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleRegister")()
	if c.registrationDisabled() {
		writeRegistrationDisabled(w)
		return
	}
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	params := extractOAuthParamsFromForm(r)
	if !c.botOK(w, r, username) {
		return
	}

	var err error
	if c.account != nil {
		_, err = c.account.Register(username, password, email, "")
	} else {
		_, err = c.userSvc.CreateUser(username, password, email, "")
	}
	if err != nil {
		if errors.Is(err, service.ErrRegistrationDisabled) {
			writeRegistrationDisabled(w)
			return
		}
		c.renderPage(w, r, "register.html", "Register", "Create Account", params, map[string]any{
			"Error": err.Error(),
		})
		return
	}

	// Registration successful. Keep the OAuth request, not the password.
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	loginURL := "/login"
	if encoded := q.Encode(); encoded != "" {
		loginURL += "?" + encoded
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// ──────────────────────────────────────────────
// Organization selector
// ──────────────────────────────────────────────

func (c *WebController) HandleOrgSelectPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleOrgSelectPage")()
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.URL.RawQuery, http.StatusFound)
		return
	}
	params := c.oauthParams(r, false)
	needs, err := c.oauthHandler.NeedsOrgChoice(params["client_id"], session.UserID, params["organization"])
	if err != nil {
		c.renderOrganization(w, r, params, session.Username, nil, "Could not load organizations")
		return
	}
	if !needs {
		http.Redirect(w, r, c.buildAuthorizeURL(params), http.StatusFound)
		return
	}
	orgs, err := c.oauthHandler.UserOrgs(session.UserID)
	if err != nil {
		c.renderOrganization(w, r, params, session.Username, nil, "Could not load organizations")
		return
	}
	if len(orgs) < 2 {
		http.Redirect(w, r, c.buildAuthorizeURL(params), http.StatusFound)
		return
	}
	c.renderOrganization(w, r, params, session.Username, orgs, "")
}

func (c *WebController) HandleOrgSelect(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleOrgSelect")()
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
		return
	}
	params := extractOAuthParamsFromForm(r)
	chosen := postedOrganization(r)
	orgs, err := c.oauthHandler.UserOrgs(session.UserID)
	if err != nil {
		c.renderOrganization(w, r, params, session.Username, orgs, "Could not load organizations")
		return
	}
	var match *models.Organization
	for _, org := range orgs {
		if org.Slug == chosen || org.ID == chosen {
			match = org
			break
		}
	}
	if match == nil {
		c.renderOrganization(w, r, params, session.Username, orgs, "Choose an organization you belong to")
		return
	}
	params["organization"] = match.Slug
	http.Redirect(w, r, c.buildAuthorizeURL(params), http.StatusFound)
}

func (c *WebController) renderOrganization(w http.ResponseWriter, r *http.Request, params map[string]string, username string, orgs []*models.Organization, message string) {
	defer telemetry.Step("controller.WebController.renderOrganization")()
	if orgs == nil {
		orgs = []*models.Organization{}
	}
	c.renderPage(w, r, "organization.html", "Organization", "Choose an organization", params, map[string]any{
		"Username": username,
		"Orgs":     orgs,
		"Error":    message,
	})
}

// postedOrganization returns the last non-empty organization value.
// The shared hidden field is submitted before the selected radio button.
func postedOrganization(r *http.Request) string {
	defer telemetry.Step("controller.postedOrganization")()
	chosen := ""
	for _, value := range r.Form["organization"] {
		value = strings.TrimSpace(value)
		if value != "" {
			chosen = value
		}
	}
	return chosen
}

func (c *WebController) oauthParams(r *http.Request, fromForm bool) map[string]string {
	defer telemetry.Step("controller.WebController.oauthParams")()
	params := extractOAuthParams(r)
	if fromForm {
		params = extractOAuthParamsFromForm(r)
	}
	if requestURI := params["request_uri"]; requestURI != "" && c.oauthHandler != nil {
		if par, err := c.oauthHandler.GetPARParams(requestURI); err == nil {
			for k, v := range par {
				if params[k] == "" {
					params[k] = v
				}
			}
		}
	}
	return params
}

// ──────────────────────────────────────────────
// Consent Flow
// ──────────────────────────────────────────────

func (c *WebController) HandleConsentPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleConsentPage")()
	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	params := extractOAuthParams(r)
	if c.oauthHandler != nil {
		c.oauthHandler.ApplyRequestObject(params)
	}

	// If PAR, fetch stored params and merge (scope, redirect_uri, etc. are in PAR, not URL)
	if requestURI := params["request_uri"]; requestURI != "" {
		if par, err := c.oauthHandler.GetPARParams(requestURI); err == nil {
			for k, v := range par {
				if params[k] == "" {
					params[k] = v
				}
			}
		}
	}

	actorName := ""
	if id := params["requested_actor"]; id != "" && c.oauthHandler != nil {
		actorName = c.oauthHandler.ClientName(id)
	}
	c.renderPage(w, r, "consent.html", "Authorize", "Authorize Access", params, map[string]any{
		"Username":  session.Username,
		"Scopes":    strings.Split(params["scope"], " "),
		"ActorName": actorName,
	})
}

func (c *WebController) HandleConsent(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandleConsent")()
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	action := r.FormValue("action")
	params := extractOAuthParamsFromForm(r)
	if c.oauthHandler != nil {
		c.oauthHandler.ApplyRequestObject(params)
	}

	session := c.getSession(r)
	if session == nil || !session.Authenticated {
		http.Redirect(w, r, "/login?"+r.Form.Encode(), http.StatusFound)
		return
	}

	if action == "deny" {
		redirectURI := params["redirect_uri"]
		state := params["state"]
		if c.oauthHandler != nil && oauth.IsOutOfBandRedirect(redirectURI) && isValidRedirectURI(redirectURI, c.clientRedirects(params["client_id"])) {
			c.oauthHandler.RenderOutOfBand(w, params["client_id"], "", state, "access_denied", "User denied the request")
			return
		}
		if isValidRedirectURI(redirectURI, c.clientRedirects(params["client_id"])) {
			errorURL := redirectURI
			if strings.Contains(errorURL, "?") {
				errorURL += "&"
			} else {
				errorURL += "?"
			}
			errorURL += "error=access_denied&error_description=User+denied+the+request"
			if state != "" {
				errorURL += "&state=" + url.QueryEscape(state)
			}
			if isValidRedirectURL(errorURL) {
				http.Redirect(w, r, errorURL, http.StatusFound)
				return
			}
		}
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// If PAR, fetch stored params to get real scope, redirect_uri, etc.
	if requestURI := params["request_uri"]; requestURI != "" {
		if par, err := c.oauthHandler.GetPARParams(requestURI); err == nil {
			for k, v := range par {
				if params[k] == "" {
					params[k] = v
				}
			}
		}
	}

	// Consent approved → persist consent
	clientID := params["client_id"]
	scope := params["scope"]
	if clientID != "" && scope != "" {
		scopes := strings.Split(scope, " ")
		_ = c.oauthHandler.SaveConsent(session.UserID, clientID, scopes)
	}
	if params["requested_actor"] != "" {
		c.oauthHandler.GrantActorConsent(session.ID, clientID, params["requested_actor"])
	}

	// prompt=consent forced this screen. Leaving it on the authorize URL
	// shows the screen again instead of issuing a code.
	params["prompt"] = stripPromptValue(params["prompt"], "consent")

	// Redirect to authorize
	authorizeURL := c.buildAuthorizeURL(params)
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// stripPromptValue removes one space-delimited prompt token.
func stripPromptValue(prompt, drop string) string {
	defer telemetry.Step("controller.stripPromptValue")()
	if prompt == "" || drop == "" {
		return prompt
	}
	kept := make([]string, 0, 2)
	for _, part := range strings.Fields(prompt) {
		if part != drop {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}
