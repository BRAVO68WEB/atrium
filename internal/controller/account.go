package controller

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/auth"
	"github.com/bravo68web/atrium/internal/branding"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/handlers/oauth"
	"github.com/bravo68web/atrium/internal/mailer"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

type AccountController struct {
	account   *service.AccountService
	users     *service.UserService
	sessions  *service.SessionService
	tokens    *repository.TokenRepository
	totp      *service.TOTPService
	oauth     *oauth.Handler
	templates *template.Template
	theme     branding.Theme
	cfg       *config.Config
	audit     *service.AuditLog
	grants    *service.GrantService
}

func (c *AccountController) SetGrants(g *service.GrantService) {
	defer telemetry.Step("controller.AccountController.SetGrants")()
	if c != nil {
		c.grants = g
	}
}

func (c *AccountController) SetAudit(a *service.AuditLog) {
	defer telemetry.Step("controller.AccountController.SetAudit")()
	if c != nil {
		c.audit = a
	}
}

func NewAccountController(
	account *service.AccountService,
	users *service.UserService,
	sessions *service.SessionService,
	tokens *repository.TokenRepository,
	totp *service.TOTPService,
	oauthHandler *oauth.Handler,
	templates *template.Template,
	cfg *config.Config,
) *AccountController {
	defer telemetry.Step("controller.NewAccountController")()
	return &AccountController{
		account:   account,
		users:     users,
		sessions:  sessions,
		tokens:    tokens,
		totp:      totp,
		oauth:     oauthHandler,
		templates: templates,
		theme:     branding.Prepare(cfg),
		cfg:       cfg,
	}
}

func (c *AccountController) HandleRegister(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleRegister")()
	if c.account != nil && c.account.RegistrationDisabled() {
		writeError(w, http.StatusForbidden, "registration_disabled", "Registration is disabled")
		return
	}
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Email       string `json:"email"`
		PhoneNumber string `json:"phone_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	user, err := c.account.Register(req.Username, req.Password, req.Email, req.PhoneNumber)
	if errors.Is(err, service.ErrRegistrationDisabled) {
		writeError(w, http.StatusForbidden, "registration_disabled", "Registration is disabled")
		return
	}
	if writePassword(w, err) {
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (c *AccountController) HandleForgot(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleForgot")()
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	id := req.Username
	if id == "" {
		id = req.Email
	}
	c.writeForgot(w, r, id)
}

func (c *AccountController) HandleReset(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleReset")()
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	c.writeReset(w, r, req.Token, req.Password)
}

func (c *AccountController) HandleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleVerifyEmail")()
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if err := c.account.Verify(req.Token); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid or expired token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *AccountController) HandleMe(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleMe")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	body := publicUser(user)
	if c.totp != nil {
		enabled, _ := c.totp.IsMFAEnabled(user.ID)
		body["mfa_enabled"] = enabled
	}
	writeJSON(w, http.StatusOK, body)
}

func (c *AccountController) HandlePatchMe(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandlePatchMe")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	var req userPatch
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	emailChanged := applyProfile(user, req)
	if emailChanged {
		user.EmailVerified = false
	}
	if err := c.users.UpdateProfile(user); err != nil {
		if writeProfileError(w, err) {
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update profile")
		return
	}
	if emailChanged {
		_ = c.account.SendVerification(user)
	}
	writeJSON(w, http.StatusOK, publicUser(user))
}

func (c *AccountController) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleChangePassword")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	tok := auth.TokenFrom(r.Context())
	keep := ""
	if tok != nil {
		keep = tok.Token
	}
	keepSID := ""
	if sess := c.oauth.GetSession(r); sess != nil {
		keepSID = sess.ID
	}
	if err := c.account.ChangePassword(user.ID, req.CurrentPassword, req.NewPassword, keep, keepSID); err != nil {
		if writePassword(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if c.audit != nil {
		c.audit.Write("user", user.ID, "password.change", "user", user.ID, r, map[string]any{"username": user.Username})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *AccountController) HandleResend(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleResend")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	if err := c.account.SendVerification(user); err != nil {
		if errors.Is(err, mailer.ErrDisabled) {
			writeError(w, http.StatusServiceUnavailable, "mailer_disabled", "SMTP is not configured")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *AccountController) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleListSessions")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	sessions, err := c.sessions.List(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list sessions")
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (c *AccountController) HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleRevokeSession")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	sid := chi.URLParam(r, "sid")
	if err := c.account.RevokeSession(user.ID, sid); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Session not found")
		return
	}
	if c.audit != nil {
		c.audit.Write("user", user.ID, "session.revoke", "session", sid, r, map[string]any{})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (c *AccountController) HandleListRefresh(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleListRefresh")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	tokens, err := c.tokens.ListRefreshTokens("", user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list refresh tokens")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (c *AccountController) HandleRevokeRefresh(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleRevokeRefresh")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	rt, err := c.tokens.GetRefreshByID(chi.URLParam(r, "id"))
	if err != nil || rt.UserID != user.ID {
		writeError(w, http.StatusNotFound, "not_found", "Refresh token not found")
		return
	}
	_ = c.tokens.RevokeRefreshToken(rt.Token)
	if rt.AccessToken != "" {
		_ = c.tokens.RevokeAccessToken(rt.AccessToken)
	}
	if c.audit != nil {
		c.audit.Write("user", user.ID, "token.revoke", "refresh_token", rt.ID, r, map[string]any{})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (c *AccountController) HandleLoginAnalytics(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleLoginAnalytics")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	window, err := loginWindow(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	report, err := c.account.LoginAnalytics(user.ID, window)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to build login analytics")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (c *AccountController) HandleActivity(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleActivity")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := c.account.Activity(user.ID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list activity")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (c *AccountController) HandleForgotPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleForgotPage")()
	c.render(w, r, "forgot.html", map[string]any{"Error": "", "Status": ""})
}

func (c *AccountController) HandleForgotSubmit(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleForgotSubmit")()
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	username := r.FormValue("username")
	if !c.botOK(w, r, username) {
		return
	}
	err := c.account.Forgot(username, c.account.RequestIP(r))
	if errors.Is(err, mailer.ErrDisabled) {
		c.render(w, r, "forgot.html", map[string]any{"Error": "Password reset email is not configured on this server.", "Status": ""})
		return
	}
	if errors.Is(err, service.ErrRateLimited) {
		c.render(w, r, "forgot.html", map[string]any{"Error": "Too many requests. Try again later.", "Status": ""})
		return
	}
	if err != nil {
		c.render(w, r, "forgot.html", map[string]any{"Error": "Could not send email.", "Status": ""})
		return
	}
	c.render(w, r, "forgot.html", map[string]any{"Error": "", "Status": "If an account with that username or email exists, a reset link is on its way."})
}

func (c *AccountController) HandleResetPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleResetPage")()
	c.render(w, r, "reset.html", map[string]any{"Error": "", "Token": r.URL.Query().Get("token"), "Done": false})
}

func (c *AccountController) HandleResetSubmit(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleResetSubmit")()
	_ = r.ParseForm()
	if !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	token := r.FormValue("token")
	err := c.account.Reset(token, r.FormValue("password"), c.account.RequestIP(r))
	if err != nil {
		msg := "That reset link is invalid or has already been used."
		if errors.Is(err, service.ErrRateLimited) {
			msg = "Too many requests. Try again later."
		}
		var pe *service.PasswordError
		if errors.As(err, &pe) {
			msg = pe.Error()
		}
		c.render(w, r, "reset.html", map[string]any{"Error": msg, "Token": token, "Done": false})
		return
	}
	if c.audit != nil {
		c.audit.Write("user", "", "password.reset", "user", "", r, map[string]any{})
	}
	c.render(w, r, "reset.html", map[string]any{"Error": "", "Token": "", "Done": true})
}

func (c *AccountController) HandleProfile(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleProfile")()
	session := c.browserSession(r)
	if session == nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/profile"), http.StatusFound)
		return
	}
	user, _ := c.users.GetUser(session.UserID)
	c.renderProfile(w, r, session, user, r.URL.Query().Get("removed") == "1", "", profileStatus(r.URL.Query().Get("status")))
}

func (c *AccountController) HandleProfileRevoke(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleProfileRevoke")()
	c.postProfile(w, r, func(session *oauth.Session) (string, string) {
		clientID := strings.TrimSpace(r.Form.Get("client_id"))
		if clientID == "" || c.grants == nil {
			return "", "Choose an application to remove"
		}
		if err := c.grants.Revoke(session.UserID, clientID); err != nil {
			return "", "Could not remove access"
		}
		if c.audit != nil {
			c.audit.Write("user", session.UserID, "consent.revoke", "client", clientID, r, nil)
		}
		return "/profile?removed=1", ""
	})
}

func (c *AccountController) HandleProfilePassword(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleProfilePassword")()
	c.postProfile(w, r, func(session *oauth.Session) (string, string) {
		err := c.account.ChangePassword(session.UserID, r.Form.Get("current_password"), r.Form.Get("new_password"), "", session.ID)
		if err != nil {
			return "", err.Error()
		}
		if c.audit != nil {
			c.audit.Write("user", session.UserID, "password.change", "user", session.UserID, r, nil)
		}
		return "/profile?status=password", ""
	})
}

func (c *AccountController) HandleProfileEmail(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleProfileEmail")()
	c.postProfile(w, r, func(session *oauth.Session) (string, string) {
		user, err := c.users.GetUser(session.UserID)
		if err != nil {
			return "", "Could not load the account"
		}
		if err := c.account.SendVerification(user); err != nil {
			if errors.Is(err, mailer.ErrDisabled) {
				return "", "SMTP is not configured"
			}
			return "", err.Error()
		}
		return "/profile?status=email", ""
	})
}

func (c *AccountController) HandleProfileMFA(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleProfileMFA")()
	c.postProfile(w, r, func(session *oauth.Session) (string, string) {
		if c.totp == nil {
			return "", "Authenticator is not available"
		}
		ok, err := c.totp.VerifyLogin(session.UserID, strings.TrimSpace(r.Form.Get("code")))
		if err != nil || !ok {
			return "", "Code is wrong"
		}
		if err := c.totp.DisableMFA(session.UserID); err != nil {
			return "", "Could not remove the authenticator"
		}
		if c.audit != nil {
			c.audit.Write("user", session.UserID, "mfa.disable", "user", session.UserID, r, nil)
		}
		return "/profile?status=mfa", ""
	})
}

func (c *AccountController) HandleProfileSession(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleProfileSession")()
	c.postProfile(w, r, func(session *oauth.Session) (string, string) {
		sid := strings.TrimSpace(r.Form.Get("session_id"))
		if sid == "" {
			return "", "Choose a browser to sign out"
		}
		if sid == session.ID {
			return "", "This browser stays signed in"
		}
		if err := c.account.RevokeSession(session.UserID, sid); err != nil {
			return "", "Session not found"
		}
		if c.audit != nil {
			c.audit.Write("user", session.UserID, "session.revoke", "session", sid, r, nil)
		}
		return "/profile?status=session", ""
	})
}

func (c *AccountController) postProfile(w http.ResponseWriter, r *http.Request, act func(*oauth.Session) (string, string)) {
	defer telemetry.Step("controller.AccountController.postProfile")()
	session := c.browserSession(r)
	if session == nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape("/profile"), http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil || !csrfOK(r) {
		rejectCSRF(w)
		return
	}
	next, message := act(session)
	if next != "" {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	user, _ := c.users.GetUser(session.UserID)
	c.renderProfile(w, r, session, user, false, message, "")
}

func (c *AccountController) HandleListMyConsents(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleListMyConsents")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	grants, err := c.grantList(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list consents")
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

func (c *AccountController) HandleRevokeMyConsent(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleRevokeMyConsent")()
	user, ok := c.caller(w, r)
	if !ok {
		return
	}
	clientID := strings.TrimSpace(chi.URLParam(r, "clientID"))
	if clientID == "" || c.grants == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	if err := c.grants.Revoke(user.ID, clientID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to revoke consent")
		return
	}
	if c.audit != nil {
		c.audit.Write("user", user.ID, "consent.revoke", "client", clientID, r, nil)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (c *AccountController) browserSession(r *http.Request) *oauth.Session {
	defer telemetry.Step("controller.AccountController.browserSession")()
	if c == nil || c.oauth == nil {
		return nil
	}
	session := c.oauth.GetSession(r)
	if session == nil || !session.Authenticated || session.UserID == "" {
		return nil
	}
	return session
}

func (c *AccountController) grantList(userID string) ([]service.GrantedApp, error) {
	defer telemetry.Step("controller.AccountController.grantList")()
	if c.grants == nil {
		return nil, nil
	}
	return c.grants.List(userID)
}

type profileGrant struct {
	ClientID string
	Name     string
	Initial  string
	Detail   string
	Color    string
}

func profileStatus(raw string) string {
	defer telemetry.Step("controller.profileStatus")()
	switch raw {
	case "password":
		return "Password updated."
	case "session":
		return "That browser was signed out."
	case "mfa":
		return "Authenticator removed."
	case "email":
		return "Verification email sent."
	default:
		return ""
	}
}

type profileSession struct {
	ID      string
	Detail  string
	Current bool
}

func (c *AccountController) renderProfile(w http.ResponseWriter, r *http.Request, session *oauth.Session, user *models.User, removed bool, message, status string) {
	defer telemetry.Step("controller.AccountController.renderProfile")()
	email := ""
	name := session.Username
	verified := false
	if user != nil {
		email = user.Email
		verified = user.EmailVerified
		if user.Username != "" {
			name = user.Username
		}
	}
	rows, err := c.grantList(session.UserID)
	if err != nil && message == "" {
		message = "Could not load applications"
	}
	view := make([]profileGrant, 0, len(rows))
	for _, row := range rows {
		detail := strings.Join(row.Scopes, " ")
		if !row.GrantedAt.IsZero() {
			when := row.GrantedAt.UTC().Format("2 Jan 2006")
			if detail != "" {
				detail += " · " + when
			} else {
				detail = when
			}
		}
		view = append(view, profileGrant{
			ClientID: row.ClientID,
			Name:     row.Name,
			Initial:  row.Initial,
			Detail:   detail,
			Color:    (models.Organization{Name: row.Name, Slug: row.ClientID}).MarkColor(),
		})
	}
	mfaOn := false
	if c.totp != nil {
		mfaOn, _ = c.totp.IsMFAEnabled(session.UserID)
	}
	browsers := []profileSession{}
	if c.sessions != nil {
		if list, err := c.sessions.List(session.UserID); err == nil {
			for _, item := range list {
				if item == nil || item.Revoked {
					continue
				}
				browsers = append(browsers, profileSession{
					ID:      item.ID,
					Detail:  sessionDetail(item),
					Current: item.ID == session.ID,
				})
			}
		}
	}
	c.render(w, r, "profile.html", map[string]any{
		"Username":      name,
		"Email":         email,
		"EmailVerified": verified,
		"MFAEnabled":    mfaOn,
		"Sessions":      browsers,
		"Grants":        view,
		"Removed":       removed,
		"Error":         message,
		"Status":        status,
	})
}

func sessionDetail(s *models.BrowserSession) string {
	defer telemetry.Step("controller.sessionDetail")()
	parts := []string{}
	if s.IP != "" {
		parts = append(parts, s.IP)
	}
	agent := s.UserAgent
	if len(agent) > 80 {
		agent = agent[:77] + "..."
	}
	if agent != "" {
		parts = append(parts, agent)
	}
	if !s.AuthTime.IsZero() {
		parts = append(parts, s.AuthTime.UTC().Format("2 Jan 2006 15:04"))
	}
	return strings.Join(parts, " · ")
}

func (c *AccountController) HandleVerifyPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.AccountController.HandleVerifyPage")()
	err := c.account.Verify(r.URL.Query().Get("token"))
	msg := "Your email is confirmed. You can sign in."
	if err != nil {
		msg = "That confirmation link is invalid or has already been used."
	}
	c.render(w, r, "verify_email.html", map[string]any{"Message": msg})
}

func (c *AccountController) caller(w http.ResponseWriter, r *http.Request) (*models.User, bool) {
	defer telemetry.Step("controller.AccountController.caller")()
	tok := auth.TokenFrom(r.Context())
	if tok == nil || tok.UserID == "" {
		writeError(w, http.StatusUnauthorized, "invalid_token", "User token required")
		return nil, false
	}
	user, err := c.users.GetUser(tok.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "User not found")
		return nil, false
	}
	return user, true
}

func (c *AccountController) writeForgot(w http.ResponseWriter, r *http.Request, id string) {
	defer telemetry.Step("controller.AccountController.writeForgot")()
	err := c.account.Forgot(id, c.account.RequestIP(r))
	if errors.Is(err, mailer.ErrDisabled) {
		writeError(w, http.StatusServiceUnavailable, "mailer_disabled", "SMTP is not configured")
		return
	}
	if errors.Is(err, service.ErrRateLimited) {
		writeError(w, http.StatusTooManyRequests, "slow_down", "Too many requests")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to send email")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *AccountController) writeReset(w http.ResponseWriter, r *http.Request, token, password string) {
	defer telemetry.Step("controller.AccountController.writeReset")()
	err := c.account.Reset(token, password, c.account.RequestIP(r))
	if errors.Is(err, service.ErrRateLimited) {
		writeError(w, http.StatusTooManyRequests, "slow_down", "Too many requests")
		return
	}
	if writePassword(w, err) {
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid or expired token")
		return
	}
	if c.audit != nil {
		c.audit.Write("user", "", "password.reset", "user", "", r, map[string]any{})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *AccountController) botOK(w http.ResponseWriter, r *http.Request, username string) bool {
	defer telemetry.Step("controller.AccountController.botOK")()
	if c == nil || c.cfg == nil || c.cfg.Security.BotProtection.Provider == "" {
		return true
	}
	if err := service.VerifyBot(r.Context(), c.cfg.Security.BotProtection, r.FormValue("bot_token"), r.RemoteAddr); err != nil {
		if username != "" && c.users != nil {
			if existing, lookupErr := c.users.GetUserByUsername(username); lookupErr == nil && c.account != nil {
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

func (c *AccountController) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	defer telemetry.Step("controller.AccountController.render")()
	if c.templates == nil {
		http.Error(w, "template unavailable", http.StatusInternalServerError)
		return
	}
	m, _ := data.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	title, heading := accountChrome(name)
	c.theme.Apply(m, title, heading, "")
	secure := c.cfg != nil && c.cfg.Server.TLS.Enabled
	m["CSRFToken"] = issueCSRF(w, r, secure)
	if name == "forgot.html" && c.cfg != nil {
		m["BotProvider"] = c.cfg.Security.BotProtection.Provider
		m["BotSiteKey"] = c.cfg.Security.BotProtection.SiteKey
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.templates.ExecuteTemplate(w, name, m); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func accountChrome(name string) (string, string) {
	defer telemetry.Step("controller.accountChrome")()
	switch name {
	case "forgot.html":
		return "Forgot Password", "Reset password"
	case "reset.html":
		return "Choose a Password", "Choose a new password"
	case "verify_email.html":
		return "Email Confirmation", "Email confirmation"
	case "profile.html":
		return "Account", "Your account"
	default:
		return "Atrium", "Atrium"
	}
}

type userPatch struct {
	Email         *string `json:"email"`
	PhoneNumber   *string `json:"phone_number"`
	GivenName     *string `json:"given_name"`
	FamilyName    *string `json:"family_name"`
	Disabled      *bool   `json:"disabled"`
	EmailVerified *bool   `json:"email_verified"`
}

func applyProfile(user *models.User, req userPatch) bool {
	defer telemetry.Step("controller.applyProfile")()
	emailChanged := false
	if req.Email != nil && *req.Email != user.Email {
		user.Email = *req.Email
		emailChanged = true
	}
	if req.PhoneNumber != nil {
		user.PhoneNumber = *req.PhoneNumber
	}
	if req.GivenName != nil {
		user.GivenName = *req.GivenName
	}
	if req.FamilyName != nil {
		user.FamilyName = *req.FamilyName
	}
	if req.EmailVerified != nil {
		user.EmailVerified = *req.EmailVerified
	}
	if req.Disabled != nil {
		user.Disabled = *req.Disabled
	}
	return emailChanged
}

func publicUser(user *models.User) map[string]any {
	defer telemetry.Step("controller.publicUser")()
	var last any
	if user.LastLoginAt != nil {
		last = user.LastLoginAt.Format(time.RFC3339)
	}
	return map[string]any{
		"id":             user.ID,
		"username":       user.Username,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"phone_number":   user.PhoneNumber,
		"given_name":     user.GivenName,
		"family_name":    user.FamilyName,
		"disabled":       user.Disabled,
		"last_login_at":  last,
		"created_at":     user.CreatedAt,
	}
}

func SafeNext(raw string) string {
	defer telemetry.Step("controller.SafeNext")()
	if raw == "" || strings.HasPrefix(raw, "//") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		return ""
	}
	if u.Path != "/device" && u.Path != "/oauth/authorize" && u.Path != "/push/enroll" && u.Path != "/push/approve" && u.Path != "/profile" {
		return ""
	}
	return u.RequestURI()
}

func loginWindow(r *http.Request) (time.Duration, error) {
	defer telemetry.Step("controller.loginWindow")()
	raw := r.URL.Query().Get("window")
	if raw == "" {
		return 30 * 24 * time.Hour, nil
	}
	window, err := time.ParseDuration(raw)
	if err != nil || window <= 0 {
		return 0, errors.New("window must be a positive duration such as 168h")
	}
	return window, nil
}
