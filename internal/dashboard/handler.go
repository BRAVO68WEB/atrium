// Package dashboard is the operator console served at /dashboard.
// The browser signs in with the management client id and secret. The React
// app is embedded in the atrium binary when it is built with -tags embed.
package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/branding"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/social"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// Clients checks a management client id and secret.
type Clients interface {
	ValidateClient(id, secret string) (*models.Client, error)
}

// Issuer mints a client-credentials access token.
type Issuer func(id, secret string) (token string, status int, detail string)

// UserOrgs lists organizations for one user. It is nil when organizations are off.
type UserOrgs func(userID string) ([]*models.Organization, error)

// Resources serves one API resource when the URI contains slashes.
type Resources interface {
	HandleGetResource(http.ResponseWriter, *http.Request)
	HandleUpdateResource(http.ResponseWriter, *http.Request)
	HandleDeleteResource(http.ResponseWriter, *http.Request)
}

// Handler is the console. API is the process router. Calls into it carry the
// management bearer token from the console session.
type Handler struct {
	cfg       *config.Config
	clients   Clients
	issue     Issuer
	api       http.Handler
	orgs      UserOrgs
	resources Resources
	pages     Pages
	store     *Store
	secure    bool
	inDocker  bool
}

type Options struct {
	Config    *config.Config
	Clients   Clients
	Issue     Issuer
	API       http.Handler
	Orgs      UserOrgs
	Resources Resources
	Pages     Pages
	Secure    bool
	InDocker  bool
}

func New(opt Options) *Handler {
	ttl := 8 * time.Hour
	if opt.Config != nil && opt.Config.Dashboard.SessionLifetime > 0 {
		ttl = opt.Config.Dashboard.SessionLifetime
	}
	return &Handler{
		cfg: opt.Config, clients: opt.Clients, issue: opt.Issue, api: opt.API,
		orgs: opt.Orgs, resources: opt.Resources, pages: opt.Pages, store: NewStore(ttl),
		secure: opt.Secure, inDocker: opt.InDocker,
	}
}

// InDocker reports whether this process should offer a container restart.
func InDocker() bool {
	if os.Getenv("ATRIUM_IN_DOCKER") == "1" {
		return true
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// Mount registers the console. Call it only when dashboard.enabled is true.
func (h *Handler) Mount(r chi.Router) {
	r.Route("/dashboard", func(d chi.Router) {
		d.Get("/brand", h.brand)
		d.Post("/session", h.login)
		d.Post("/logout", h.logout)
		d.Route("/api", func(api chi.Router) {
			api.Use(h.requireSession)
			api.Get("/meta", h.meta)
			api.Get("/config", h.getConfig)
			api.Put("/config", h.putConfig)
			api.Post("/restart", h.restart)
			api.Post("/social/discover", h.discoverSocial)
			api.Get("/themes/pages", h.themePages)
			api.Get("/themes/email", h.themeEmail)
			api.Get("/users/{userID}/organizations", h.userOrgs)
			api.Method(http.MethodGet, "/resource", http.HandlerFunc(h.resource))
			api.Method(http.MethodPut, "/resource", http.HandlerFunc(h.resource))
			api.Method(http.MethodDelete, "/resource", http.HandlerFunc(h.resource))
			api.HandleFunc("/*", h.proxy)
		})
		d.Group(func(preview chi.Router) {
			preview.Use(h.requireSession)
			preview.Get("/preview/pages/{name}", h.previewPage)
			preview.Get("/preview/email/{name}", h.previewEmail)
		})
		d.Get("/", h.serve)
		d.Get("/*", h.serve)
	})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.login")()
	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	client, err := h.clients.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil || client == nil {
		writeErr(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}
	if client.TokenEndpointAuthMethod == "none" || !service.HasGrant(client.GrantTypes, "client_credentials") || !service.HasScope(client.Scopes, service.ManagementScope) {
		writeErr(w, http.StatusForbidden, "insufficient_scope", "A management client-credentials token is required")
		return
	}
	token, status, detail := h.issue(req.ClientID, req.ClientSecret)
	if token == "" {
		if status == 0 {
			status = http.StatusUnauthorized
		}
		if detail == "" {
			detail = "Invalid client credentials"
		}
		writeErr(w, status, "invalid_client", detail)
		return
	}
	csrf := randomID()
	id, exp := h.store.Put(token, client.ID, csrf)
	h.setCookies(w, id, csrf, exp)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "csrf": csrf})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.logout")()
	item, ok := h.store.Get(readCookie(r, sessionCookie))
	if !ok || !csrfOK(r, item.CSRF) {
		writeErr(w, http.StatusForbidden, "invalid_request", "CSRF token is missing")
		return
	}
	h.store.Delete(readCookie(r, sessionCookie))
	clearCookies(w, h.secure)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		item, ok := h.store.Get(readCookie(r, sessionCookie))
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid_token", "Sign in to the dashboard")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !csrfOK(r, item.CSRF) {
			writeErr(w, http.StatusForbidden, "invalid_request", "CSRF token is missing")
			return
		}
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), item)))
	})
}

func (h *Handler) brand(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.brand")()
	writeJSON(w, http.StatusOK, publicBrand(h.cfg))
}

func publicBrand(cfg *config.Config) map[string]any {
	view := branding.Prepare(cfg).Snapshot()
	return map[string]any{
		"product_name":     view.ProductName,
		"primary_color":    view.PrimaryColor,
		"background_color": view.BackgroundColor,
		"text_color":       view.TextColor,
		"logo_url":         view.LogoURL,
		"favicon_url":      view.FaviconURL,
		"footer_text":      view.FooterText,
	}
}

func (h *Handler) meta(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.meta")()
	cfg := h.cfg
	issuer := strings.TrimRight(cfg.OIDC.Issuer, "/")
	if issuer == "" {
		issuer = strings.TrimRight(cfg.Security.Issuer, "/")
	}
	brand := publicBrand(cfg)
	csrf := ""
	if item, ok := sessionFrom(r.Context()); ok {
		csrf = item.CSRF
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"product_name":         brand["product_name"],
		"brand":                brand,
		"csrf":                 csrf,
		"org_enabled":          cfg.Org.Enabled,
		"org_autolookup":       cfg.Org.EnabledDomainBasedAutolookup,
		"mfa_enabled":          cfg.Security.MFA.Enabled,
		"management_client_id": cfg.Management.ClientID,
		"issuer":               issuer,
		"endpoints":            endpoints(issuer, cfg.Push.Enabled),
		"grant_types":          cfg.OIDC.SupportedGrantTypes,
		"auth_methods":         cfg.OIDC.SupportedAuthMethods,
		"webhook_events":       service.KnownWebhookEvents(),
		"in_docker":            h.inDocker,
		"embedded":             uiEmbedded(),
		"config_path":          h.configPath(),
	})
}

func endpoints(issuer string, push bool) map[string]string {
	if issuer == "" {
		return map[string]string{}
	}
	out := map[string]string{
		"issuer":       issuer,
		"authorize":    issuer + "/oauth/authorize",
		"token":        issuer + "/oauth/token",
		"revoke":       issuer + "/oauth/revoke",
		"introspect":   issuer + "/oauth/introspect",
		"jwks":         issuer + "/oidc/jwks",
		"userinfo":     issuer + "/oidc/userinfo",
		"device":       issuer + "/oauth/device",
		"par":          issuer + "/oauth/par",
		"bc_authorize": issuer + "/oauth/bc-authorize",
		"register":     issuer + "/oauth/register",
		"discovery":    issuer + "/.well-known/openid-configuration",
		"as_metadata":  issuer + "/.well-known/oauth-authorization-server",
	}
	if push {
		out["push_discovery"] = issuer + "/.well-known/oauth-push-notification"
	}
	return out
}

func (h *Handler) discoverSocial(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.Handler.discoverSocial")()
	var req struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	doc, err := social.DiscoverIssuer(r.Context(), req.Issuer)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (h *Handler) userOrgs(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.userOrgs")()
	if h.orgs == nil || !h.cfg.Org.Enabled {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	orgs, err := h.orgs(chi.URLParam(r, "userID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if orgs == nil {
		orgs = []*models.Organization{}
	}
	writeJSON(w, http.StatusOK, orgs)
}

func (h *Handler) resource(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.resource")()
	if h.resources == nil {
		writeErr(w, http.StatusNotFound, "not_found", "Resource is not available")
		return
	}
	uri := r.URL.Query().Get("uri")
	if uri == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "uri is required")
		return
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("uri", uri)
	req := r.WithContext(contextWithRoute(r.Context(), rctx))
	switch r.Method {
	case http.MethodGet:
		h.resources.HandleGetResource(w, req)
	case http.MethodPut:
		h.resources.HandleUpdateResource(w, req)
	default:
		h.resources.HandleDeleteResource(w, req)
	}
}

func (h *Handler) restart(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.restart")()
	if !h.inDocker {
		writeErr(w, http.StatusConflict, "restart_required", "Restart the atrium process to apply the saved config")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "restarting"})
	go func() {
		time.Sleep(250 * time.Millisecond)
		signalStop()
	}()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
