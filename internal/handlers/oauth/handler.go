package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/atrium/internal/branding"
	"github.com/bravo68web/atrium/internal/cache"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/queue"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
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
	defer telemetry.Step("oauth.Handler.SetDeviceLogin")()
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
	defer telemetry.Step("oauth.NewHandler")()
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
	defer telemetry.Step("oauth.Handler.SetOrgs")()
	if h != nil {
		h.orgs = orgs
	}
}

func (h *Handler) ClientName(id string) string {
	defer telemetry.Step("oauth.Handler.ClientName")()
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
	defer telemetry.Step("oauth.Handler.ClientRedirectURIs")()
	if h == nil || id == "" {
		return nil
	}
	client, code, _ := h.resolveClient(context.Background(), id, "")
	if code != "" || client == nil {
		return nil
	}
	out := make([]string, len(client.RedirectURIs))
	copy(out, client.RedirectURIs)
	return out
}

func (h *Handler) xaa() *service.XAA {
	defer telemetry.Step("oauth.Handler.xaa")()
	if h == nil {
		return nil
	}
	return service.NewXAA(h.cfg, h.userRepo, h.cimd)
}

func (h *Handler) SetCache(c cache.Cache) {
	defer telemetry.Step("oauth.Handler.SetCache")()
	if h != nil && c != nil {
		h.cimd = c
	}
}

func (h *Handler) SetTemplates(t *template.Template) {
	defer telemetry.Step("oauth.Handler.SetTemplates")()
	h.pages = t
}

func (h *Handler) SetWebhooks(d *service.WebhookDispatcher) {
	defer telemetry.Step("oauth.Handler.SetWebhooks")()
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

func (h *Handler) getSession(r *http.Request) *Session {
	defer telemetry.Step("oauth.Handler.getSession")()
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
	defer telemetry.Step("oauth.Handler.GetSession")()
	return h.getSession(r)
}

func (h *Handler) SetSession(w http.ResponseWriter, userID, username string) {
	defer telemetry.Step("oauth.Handler.SetSession")()
	h.SetSessionWithMFA(w, userID, username, true)
}

func (h *Handler) SetSessionWithMFA(w http.ResponseWriter, userID, username string, mfaVerified bool) {
	defer telemetry.Step("oauth.Handler.SetSessionWithMFA")()
	h.SetSessionRequest(w, nil, userID, username, mfaVerified)
}

func (h *Handler) SetSessionRequest(w http.ResponseWriter, r *http.Request, userID, username string, mfaVerified bool) {
	defer telemetry.Step("oauth.Handler.SetSessionRequest")()
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
	defer telemetry.Step("oauth.Handler.MarkSessionMFA")()
	cookie, err := r.Cookie("session_id")
	if err != nil || h.sessions == nil {
		return
	}
	_ = h.sessions.MarkMFA(cookie.Value)
	h.writeSessionCookie(w, cookie.Value)
}

func (h *Handler) writeSessionCookie(w http.ResponseWriter, sessionID string) {
	defer telemetry.Step("oauth.Handler.writeSessionCookie")()
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
	defer telemetry.Step("oauth.Handler.hasConsented")()
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
	defer telemetry.Step("oauth.Handler.clearSession")()
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
	defer telemetry.Step("oauth.Handler.ClearSession")()
	h.clearSession(w, r)
}

func (h *Handler) GetPARParams(requestURI string) (map[string]string, error) {
	defer telemetry.Step("oauth.Handler.GetPARParams")()
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
	defer telemetry.Step("oauth.Handler.SaveConsent")()
	return h.consentRepo.Save(userID, clientID, scopes)
}

func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleToken")()
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
	defer telemetry.Step("oauth.grant")()

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
	case config.XAAJWTBearerGrant:
		if h.cfg == nil || !h.cfg.XAA.Enabled {
			writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type: "+grantType)
			return
		}
		h.handleJWTBearer(w, r)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant type: "+grantType)
	}
}

func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleRevoke")()
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

	client, ok := h.tokenCaller(w, r)
	if !ok {
		return
	}
	clientID := client.ID

	kind := h.ownedToken(clientID, token, tokenTypeHint)
	if kind == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !h.revokeDPoP(w, r, client, token) {
		return
	}
	switch kind {
	case "refresh_token":
		if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil && rt != nil {
			_ = h.tokenRepo.RevokeRefreshToken(token)
			if rt.AccessToken != "" {
				_ = h.tokenRepo.RevokeAccessToken(rt.AccessToken)
			}
		}
	default:
		_ = h.tokenRepo.RevokeAccessToken(token)
		if rt, err := h.tokenRepo.GetRefreshTokenByAccessToken(token); err == nil && rt != nil {
			_ = h.tokenRepo.RevokeRefreshToken(rt.Token)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// ownedToken reports which token type belongs to clientID.
// RFC 7009 searches the hinted type first, then the other type.
// A token issued to someone else is treated as not found so the response
// does not reveal that the token exists.
func (h *Handler) ownedToken(clientID, token, hint string) string {
	defer telemetry.Step("oauth.Handler.ownedToken")()
	hint = strings.ToLower(strings.TrimSpace(hint))
	order := []string{"refresh_token", "access_token"}
	if hint == "access_token" {
		order = []string{"access_token", "refresh_token"}
	}
	for _, kind := range order {
		switch kind {
		case "refresh_token":
			rt, err := h.tokenRepo.GetRefreshToken(token)
			if err != nil || rt == nil {
				continue
			}
			if rt.ClientID != clientID {
				return ""
			}
			return kind
		default:
			at, err := h.tokenRepo.GetAccessToken(token)
			if err != nil || at == nil {
				continue
			}
			if at.ClientID != clientID {
				return ""
			}
			return kind
		}
	}
	return ""
}

func (h *Handler) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleIntrospect")()
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
		if result.OrgID != "" {
			result.OrgRole = h.oidcHandler.OrgRole(result.OrgID, result.Sub)
		}
		computed, err := h.oidcHandler.SubjectFor(r.Context(), result.ClientID, result.Sub)
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to resolve subject")
			return
		}
		result.Sub = computed
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleRegister")()
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
	defer telemetry.Step("oauth.isValidRedirectURI")()
	if uri == "" {
		return false
	}
	for _, allowed := range allowedURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// responseHas reports whether responseType contains part as a whole token.
// "id_token" does not contain the access-token response type "token".
func responseHas(responseType, part string) bool {
	defer telemetry.Step("oauth.responseHas")()
	for _, item := range strings.Fields(responseType) {
		if item == part {
			return true
		}
	}
	return false
}

// clientAllowsResponseType reports whether the client's grant list permits
// responseType. An empty grant list still permits every response type so
// clients created before grant_types was stored keep working.
func clientAllowsResponseType(grants []string, responseType string) bool {
	defer telemetry.Step("oauth.clientAllowsResponseType")()
	if len(grants) == 0 {
		return true
	}
	needCode := responseHas(responseType, "code")
	needImplicit := responseHas(responseType, "token") || responseHas(responseType, "id_token")
	if responseType == "none" {
		return true
	}
	hasCode := false
	hasImplicit := false
	for _, grant := range grants {
		switch grant {
		case "authorization_code":
			hasCode = true
		case "implicit":
			hasImplicit = true
		}
	}
	if needCode && !hasCode {
		return false
	}
	if needImplicit && !hasImplicit {
		return false
	}
	return needCode || needImplicit
}

func isValidURI(uri string) bool {
	defer telemetry.Step("oauth.isValidURI")()
	if IsOutOfBandRedirect(uri) {
		return true
	}
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Fragment != "" || parsed.Hostname() == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	return parsed.Scheme == "http" && parsed.Hostname() == "localhost"
}

func (h *Handler) issueAccessToken(ctx context.Context, clientID, userID, scope, tokenType string) (string, error) {
	defer telemetry.Step("oauth.Handler.issueAccessToken")()
	return h.issueAccessTokenFor(ctx, clientID, userID, scope, tokenType, "", "", "", "")
}

func (h *Handler) issueAccessTokenFor(ctx context.Context, clientID, userID, scope, tokenType, orgID, orgSlug, resource, actor string) (string, error) {
	defer telemetry.Step("oauth.Handler.issueAccessTokenFor")()
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
		return h.oidcHandler.CreateAccessTokenJWT(ctx, clientID, userID, scope, tokenType, lifetime, orgID, orgSlug, resource, actor)
	}
	return crypto.GenerateToken()
}

func actorGrantKey(sessionID, clientID, actor string) string {
	defer telemetry.Step("oauth.actorGrantKey")()
	return sessionID + "\n" + clientID + "\n" + actor
}

// GrantActorConsent remembers that this browser session just approved an actor.
func (h *Handler) GrantActorConsent(sessionID, clientID, actor string) {
	defer telemetry.Step("oauth.Handler.GrantActorConsent")()
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
	defer telemetry.Step("oauth.Handler.takeActorConsent")()
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
	defer telemetry.Step("oauth.Handler.actorSubject")()
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
	defer telemetry.Step("oauth.Handler.needsOrgChoice")()
	if h == nil || h.orgs == nil {
		return false, nil
	}
	return h.orgs.NeedsChoice(client, userID, requested)
}

// NeedsOrgChoice reports whether /organization should be shown for this
// authorize request. clientID is loaded when it names a real client.
func (h *Handler) NeedsOrgChoice(clientID, userID, requested string) (bool, error) {
	defer telemetry.Step("oauth.Handler.NeedsOrgChoice")()
	var client *models.Client
	if h != nil && clientID != "" {
		if loaded, code, _ := h.resolveClient(context.Background(), clientID, ""); code == "" {
			client = loaded
		}
	}
	return h.needsOrgChoice(client, userID, requested)
}

func (h *Handler) UserOrgs(userID string) ([]*models.Organization, error) {
	defer telemetry.Step("oauth.Handler.UserOrgs")()
	if h == nil || h.orgs == nil {
		return nil, nil
	}
	return h.orgs.ListForUser(userID)
}

func (h *Handler) orgSlug(orgID string) string {
	defer telemetry.Step("oauth.Handler.orgSlug")()
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
	defer telemetry.Step("oauth.Handler.applyOrg")()
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
	defer telemetry.Step("oauth.mustGenerateToken")()
	token, err := crypto.GenerateToken()
	if err != nil {
		return uuid.New().String()
	}
	return token
}

func hasDuplicateParams(r *http.Request) bool {
	defer
	// Check URL query parameters
	telemetry.Step("oauth.hasDuplicateParams")()

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
	defer telemetry.Step("oauth.writeOAuthError")()
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
	defer telemetry.Step("oauth.writeTokenError")()
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
	defer telemetry.Step("oauth.writeTokenResponse")()
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
	defer telemetry.Step("oauth.writeOIDCTokenResponse")()
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
	defer telemetry.Step("oauth.containsScope")()
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	defer telemetry.Step("oauth.writeJSON")()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
