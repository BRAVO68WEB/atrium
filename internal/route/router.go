package route

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"gopkg.in/yaml.v3"

	"github.com/bravo68web/atrium/internal/aauth"
	"github.com/bravo68web/atrium/internal/auth"
	"github.com/bravo68web/atrium/internal/controller"
	"github.com/bravo68web/atrium/internal/handlers/oauth"
	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/push"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/internal/version"
)

type Router struct {
	mux            *chi.Mux
	managementCtrl *controller.ManagementController
	webCtrl        *controller.WebController
	oauthHandler   *oauth.Handler
	oidcHandler    *oidc.Handler
	pushHandler    *push.Handler
	aauthHandler   *aauth.Handler
	accountCtrl    *controller.AccountController
	authn          *auth.Middleware
	openapiJSON    []byte
	templateFS     embed.FS
	csp            string
}

func (r *Router) SetContentSecurityPolicy(policy string) {
	if r != nil && policy != "" {
		r.csp = policy
	}
}

func NewRouter(
	managementCtrl *controller.ManagementController,
	webCtrl *controller.WebController,
	oauthHandler *oauth.Handler,
	oidcHandler *oidc.Handler,
	pushHandler *push.Handler,
	aauthHandler *aauth.Handler,
	accountCtrl *controller.AccountController,
	authn *auth.Middleware,
	openapiSpec []byte,
	templateFS embed.FS,
) *Router {
	openapiJSON, err := convertYAMLBytesToJSON(openapiSpec)
	if err != nil {
		log.Printf("WARNING: Failed to convert OpenAPI spec to JSON: %v", err)
		openapiJSON = []byte("{}")
	}

	r := &Router{
		mux:            chi.NewRouter(),
		managementCtrl: managementCtrl,
		webCtrl:        webCtrl,
		oauthHandler:   oauthHandler,
		oidcHandler:    oidcHandler,
		pushHandler:    pushHandler,
		aauthHandler:   aauthHandler,
		accountCtrl:    accountCtrl,
		authn:          authn,
		openapiJSON:    openapiJSON,
		templateFS:     templateFS,
		csp:            service.ContentSecurityPolicy(""),
	}

	r.setupMiddleware()
	r.setupRoutes()

	return r
}

func (r *Router) setupMiddleware() {
	r.mux.Use(telemetry.Middleware)
	r.mux.Use(middleware.RequestID)
	r.mux.Use(middleware.Recoverer)
	r.mux.Use(middleware.Timeout(60 * time.Second))

	r.mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "DPoP"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Security headers
	r.mux.Use(r.securityHeaders)
}

func (r *Router) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", r.csp)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, req)
	})
}

func (r *Router) setupRoutes() {
	r.mux.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok",
		})
	})
	r.mux.Get("/version", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, http.StatusOK, version.Current())
	})

	r.mux.Route("/api", func(r2 chi.Router) {
		MountAccountAPI(r2, r.accountCtrl, r.authn.RequireUser)
		r2.Group(func(mgmt chi.Router) {
			mgmt.Use(r.authn.RequireManagement)
			mountManagement(mgmt, r)
		})
	})

	r.mux.Route("/oauth", func(r2 chi.Router) {
		r2.Get("/authorize", r.oauthHandler.HandleAuthorize)
		r2.Post("/authorize", r.oauthHandler.HandleAuthorize)
		r2.Post("/token", r.oauthHandler.HandleToken)
		r2.Post("/revoke", r.oauthHandler.HandleRevoke)
		r2.Post("/introspect", r.oauthHandler.HandleIntrospect)
		r2.Post("/register", r.oauthHandler.HandleRegister)
		r2.Post("/device", r.oauthHandler.HandleDeviceAuthorization)
		r2.Post("/par", r.oauthHandler.HandlePAR)
		r2.Post("/bc-authorize", r.oauthHandler.HandleBCAuthorize)
		r2.Get("/oob", r.oauthHandler.HandleOOBHelper)
	})

	r.mux.Route("/device", func(r2 chi.Router) {
		r2.Get("/", r.oauthHandler.HandleDeviceVerification)
		r2.Post("/", r.oauthHandler.HandleDeviceVerification)
	})

	r.mux.Route("/ciba", func(r2 chi.Router) {
		r2.Use(r.authn.RequireManagement)
		r2.Get("/pending", r.oauthHandler.HandleCIBAListPending)
		r2.Get("/status", r.oauthHandler.HandleCIBAStatus)
		r2.Post("/approve", r.oauthHandler.HandleCIBAApprove)
		r2.Post("/deny", r.oauthHandler.HandleCIBADeny)
	})

	r.mux.Route("/.well-known", func(r2 chi.Router) {
		r2.Get("/openid-configuration", r.oidcHandler.HandleDiscovery)
		r2.Get("/oauth-authorization-server", r.oidcHandler.HandleASMetadata)
		if r.pushHandler != nil {
			r2.Get("/oauth-push-notification", r.pushHandler.Discovery)
		}
	})

	if r.pushHandler != nil {
		r.mux.Get("/push/enroll", r.webCtrl.HandlePushEnroll)
		r.mux.Get("/push/approve", r.webCtrl.HandlePushApprove)
		r.mux.Post("/push/approve", r.webCtrl.HandlePushApprove)
		r.mux.Get("/push/pending", r.pushHandler.Pending)
		r.mux.Post("/push/pending", r.pushHandler.Decide)
		r.mux.Post("/push/register", r.pushHandler.Register)
		r.mux.Post("/push/revoke", r.pushHandler.Revoke)
		r.mux.Post("/push/rotate-key", r.pushHandler.Rotate)
		r.mux.Get("/push/devices", r.pushHandler.Devices)
		r.mux.Post("/push/devices", r.pushHandler.Primary)
	}

	if r.aauthHandler != nil {
		r.aauthHandler.Mount(r.mux)
	}

	r.mux.Route("/oidc", func(r2 chi.Router) {
		r2.Get("/userinfo", r.oidcHandler.HandleUserInfo)
		r2.Get("/jwks", r.oidcHandler.HandleJWKS)
	})

	if r.webCtrl != nil && r.webCtrl.PreviewEnabled() {
		r.mux.Get("/preview", r.webCtrl.HandlePreview)
		r.mux.Get("/preview/{page}", r.webCtrl.HandlePreview)
	}
	r.mux.Get("/branding/assets/{name}", r.webCtrl.ServeBrandAsset)
	r.mux.Get("/login/social/{provider}/callback", r.webCtrl.HandleSocialCallback)
	r.mux.Get("/login/social/{provider}", r.webCtrl.HandleSocialStart)

	r.mux.Route("/login", func(r2 chi.Router) {
		r2.Get("/", r.webCtrl.HandleLoginPage)
		r2.Post("/", r.webCtrl.HandleLogin)
	})

	r.mux.Route("/login/mfa", func(r2 chi.Router) {
		r2.Post("/", r.webCtrl.HandleMFA)
	})

	r.mux.Route("/register", func(r2 chi.Router) {
		r2.Get("/", r.webCtrl.HandleRegisterPage)
		r2.Post("/", r.webCtrl.HandleRegister)
	})

	r.mux.Route("/consent", func(r2 chi.Router) {
		r2.Get("/", r.webCtrl.HandleConsentPage)
		r2.Post("/", r.webCtrl.HandleConsent)
	})

	MountBrowserExtras(r.mux, r.accountCtrl, r.oauthHandler)
	MountOrgSelector(r.mux, r.webCtrl)

	r.mux.Route("/mfa", func(r2 chi.Router) {
		r2.Get("/enroll", r.webCtrl.HandleMFAEnrollPage)
		r2.Post("/enroll/verify", r.webCtrl.HandleMFAEnrollVerify)
	})

	// OpenAPI spec as JSON
	r.mux.Get("/openapi", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(r.openapiJSON)
	})

	// OpenAPI spec as YAML
	r.mux.Get("/docs/openapi.yaml", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		http.ServeFile(w, req, "openapi/spec.yaml")
	})

	// Scalar API docs UI
	r.mux.Get("/docs", func(w http.ResponseWriter, req *http.Request) {
		tmpl, err := template.ParseFS(r.templateFS, "internal/templates/docs.html")
		if err != nil {
			http.Error(w, "Failed to load docs page", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, nil)
	})
}

func mountManagement(mgmt chi.Router, r *Router) {
	mgmt.Get("/backup", r.managementCtrl.HandleBackup)
	mgmt.Post("/restore", r.managementCtrl.HandleRestore)

	mgmt.Route("/clients", func(r3 chi.Router) {
		r3.Get("/", r.managementCtrl.HandleListClients)
		r3.Post("/", r.managementCtrl.HandleCreateClient)
		r3.Get("/{clientID}", r.managementCtrl.HandleGetClient)
		r3.Put("/{clientID}", r.managementCtrl.HandleUpdateClient)
		r3.Delete("/{clientID}", r.managementCtrl.HandleDeleteClient)
	})

	mgmt.Route("/users", func(r3 chi.Router) {
		r3.Get("/", r.managementCtrl.HandleListUsers)
		r3.Post("/", r.managementCtrl.HandleCreateUser)
		r3.Post("/import", r.managementCtrl.HandleImportUsers)
		r3.Get("/export", r.managementCtrl.HandleExportUsers)
		r3.Post("/{userID}/mfa/enable", r.managementCtrl.HandleMFAEnable)
		r3.Post("/{userID}/mfa/verify", r.managementCtrl.HandleMFAVerify)
		r3.Get("/{userID}/mfa/status", r.managementCtrl.HandleMFAStatus)
		r3.Post("/{userID}/mfa/disable", r.managementCtrl.HandleMFADisable)
		r3.Get("/{userID}", r.managementCtrl.HandleGetUser)
	})

	mgmt.Route("/tokens", func(r3 chi.Router) {
		r3.Get("/", r.managementCtrl.HandleListTokens)
		r3.Post("/{token}/revoke", r.managementCtrl.HandleRevokeToken)
	})

	mgmt.Route("/ciba", func(r3 chi.Router) {
		r3.Get("/pending", r.oauthHandler.HandleCIBAListPending)
		r3.Post("/{authReqID}/approve", r.oauthHandler.HandleCIBAApprove)
		r3.Post("/{authReqID}/deny", r.oauthHandler.HandleCIBADeny)
	})

	mgmt.Route("/scopes", func(r3 chi.Router) {
		r3.Get("/", r.managementCtrl.HandleListScopes)
		r3.Post("/", r.managementCtrl.HandleCreateScope)
		r3.Get("/{name}", r.managementCtrl.HandleGetScope)
		r3.Delete("/{name}", r.managementCtrl.HandleDeleteScope)
	})

	mgmt.Route("/resources", func(r3 chi.Router) {
		r3.Get("/", r.managementCtrl.HandleListResources)
		r3.Post("/", r.managementCtrl.HandleCreateResource)
		r3.Get("/{uri}", r.managementCtrl.HandleGetResource)
		r3.Put("/{uri}", r.managementCtrl.HandleUpdateResource)
		r3.Delete("/{uri}", r.managementCtrl.HandleDeleteResource)
		r3.Get("/{uri}/scopes", r.managementCtrl.HandleListResourceScopes)
	})

	mgmt.Route("/consents", func(r3 chi.Router) {
		r3.Get("/", r.managementCtrl.HandleListConsents)
		r3.Delete("/", r.managementCtrl.HandleRevokeConsent)
	})

	MountManagementExtras(mgmt, r.managementCtrl)
}

func (r *Router) GetMux() *chi.Mux {
	return r.mux
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func convertYAMLBytesToJSON(yamlData []byte) ([]byte, error) {
	var result map[string]interface{}
	if err := yaml.Unmarshal(yamlData, &result); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
