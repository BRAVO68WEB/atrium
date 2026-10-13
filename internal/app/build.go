// Package app wires the process into the one HTTP router.
package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	root "github.com/bravo68web/oauth-impl"
	"github.com/bravo68web/oauth-impl/internal/aauth"
	"github.com/bravo68web/oauth-impl/internal/auth"
	"github.com/bravo68web/oauth-impl/internal/cache"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/controller"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/handlers/oauth"
	"github.com/bravo68web/oauth-impl/internal/hashalgo"
	"github.com/bravo68web/oauth-impl/internal/mailer"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/push"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/route"
	"github.com/bravo68web/oauth-impl/internal/service"
)

// Built is the running HTTP application. Close releases the cache client Build opened.
type Built struct {
	Mux   *chi.Mux
	close func()
}

// Close releases resources Build opened. The database and queue stay with the caller.
func (b *Built) Close() {
	if b != nil && b.close != nil {
		b.close()
	}
}

// Build wires repositories, services, handlers, and route.NewRouter.
// cfg is normalized here. q is the approval queue the caller opened.
func Build(cfg *config.Config, db *database.DB, q queue.Queue) (*Built, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if db == nil {
		return nil, fmt.Errorf("database is required")
	}
	if q == nil {
		return nil, fmt.Errorf("queue is required")
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("working directory: %w", err)
	}
	cfg.Normalize()
	if err := config.ValidateBranding(cfg); err != nil {
		return nil, err
	}
	if err := config.ValidateSocial(cfg); err != nil {
		return nil, err
	}
	if err := config.ValidatePlatform(cfg); err != nil {
		return nil, err
	}
	if err := config.ValidatePush(cfg); err != nil {
		return nil, err
	}
	if err := config.ValidateAAuth(cfg); err != nil {
		return nil, err
	}
	if err := service.ValidateTrustedProxies(cfg.Security.TrustedProxies); err != nil {
		return nil, err
	}
	hasher, err := hashalgo.Prepare(wd, os.Getenv("HASH_ALGO"), cfg.Security.HashAlgo)
	if err != nil {
		return nil, err
	}
	log.Printf("password hasher: %s (%s)", hasher.ID(), hashalgo.CanonicalRel)

	conn := db
	clientRepo := repository.NewClientRepository(conn)
	userRepo := repository.NewUserRepository(conn)
	tokenRepo := repository.NewTokenRepository(conn)
	authCodeRepo := repository.NewAuthCodeRepository(conn)
	deviceRepo := repository.NewDeviceCodeRepository(conn)
	cibaRepo := repository.NewCIBARepository(conn)
	parRepo := repository.NewPARRepository(conn)
	consentRepo := repository.NewConsentRepository(conn)
	scopeRepo := repository.NewScopeRepository(conn)
	resourceRepo := repository.NewResourceRepository(conn)

	if err := service.SeedManagementClient(clientRepo, cfg); err != nil {
		return nil, fmt.Errorf("management client: %w", err)
	}
	if strings.TrimSpace(cfg.OIDC.PairwiseSalt) == "" {
		n, err := clientRepo.CountPairwise()
		if err != nil {
			return nil, fmt.Errorf("pairwise clients: %w", err)
		}
		if n > 0 {
			return nil, fmt.Errorf("oidc.pairwise_salt is required when a client uses subject_type pairwise")
		}
	}

	oidcHandler, err := oidc.NewHandler(db, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC handler: %w", err)
	}

	store, redisClient, err := openCache(cfg)
	if err != nil {
		return nil, err
	}
	oidcHandler.SetSectorCache(store)
	oidcHandler.SetSectorFetch(func(ctx context.Context, rawURL string) ([]byte, error) {
		body, status, err := service.FetchSafe(ctx, cfg, http.MethodGet, rawURL, nil, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("sector document returned %d", status)
		}
		return body, nil
	})

	mail, err := mailer.New(cfg.SMTP)
	if err != nil {
		closeRedis(redisClient)
		return nil, err
	}
	mailTemplates, err := mailer.Load(cfg.Email.TemplatesDir)
	if err != nil {
		closeRedis(redisClient)
		return nil, err
	}

	dpopSvc := service.NewDPoPServiceWithCache(store)
	mtlsSvc := service.NewMTLSService()
	if cfg.Server.TLS.CRLFile != "" {
		if err := mtlsSvc.SetCRLPath(cfg.Server.TLS.CRLFile); err != nil {
			log.Printf("WARNING: Failed to load CRL: %v", err)
		} else {
			log.Printf("CRL loaded from %s", cfg.Server.TLS.CRLFile)
		}
	}
	jarSvc := service.NewJARService(cfg.Security.Issuer)
	totpSvc := service.NewTOTPService(userRepo, &cfg.Security.MFA)
	userSvc := service.NewUserService(userRepo, totpSvc, &cfg.Security, hasher)
	sessionSvc := service.NewSessionService(repository.NewSessionRepository(conn), cfg.Security.SessionLifetime)
	logoutSvc := service.NewLogoutService(sessionSvc, clientRepo, oidcHandler)
	accountSvc := service.NewAccountService(userSvc, userRepo, repository.NewEmailTokenRepository(conn), repository.NewLoginEventRepository(conn), sessionSvc, tokenRepo, mail, logoutSvc, cfg)
	accountSvc.SetTemplates(mailTemplates)
	hooks := service.NewWebhookDispatcher(repository.NewWebhookRepository(conn))
	hooks.SetFetchConfig(cfg)
	logoutSvc.SetFetchConfig(cfg)
	accountSvc.SetWebhooks(hooks)
	logoutSvc.SetWebhooks(hooks)
	oidcHandler.SetDPoPCheck(func(header, method, uri, accessToken string) error {
		_, err := dpopSvc.ValidateDPoPProof(header, method, uri, accessToken)
		return err
	})
	oidc.StartRotation(oidcHandler.GetKeySet(), cfg.OIDC.KeyRotationInterval, cfg.OIDC.KeyRetain)

	oauthHandler := oauth.NewHandler(clientRepo, userRepo, tokenRepo, authCodeRepo, deviceRepo, cibaRepo, parRepo, consentRepo, dpopSvc, mtlsSvc, jarSvc, cfg, q, oidcHandler, userSvc, sessionSvc, logoutSvc, accountSvc)
	oauthHandler.SetCache(store)
	oauthHandler.SetWebhooks(hooks)
	orgs := service.NewOrgService(repository.NewOrgRepository(conn), cfg)
	oauthHandler.SetOrgs(orgs)

	clientSvc := service.NewClientService(clientRepo)
	tokenSvc := service.NewTokenService(tokenRepo)
	auditLog := service.NewAuditLog(repository.NewAuditRepository(conn))
	mgmtCtrl := controller.NewManagementController(clientSvc, userSvc, tokenSvc, totpSvc, scopeRepo, resourceRepo, consentRepo, accountSvc, sessionSvc, tokenRepo)
	mgmtCtrl.SetOrgs(orgs)
	mgmtCtrl.SetWebhooks(hooks)
	mgmtCtrl.SetAudit(auditLog)
	mgmtCtrl.SetKeys(oidcHandler.GetKeySet(), cfg.OIDC.KeyRetain)
	oauthHandler.SetAudit(auditLog)

	webCtrl, err := controller.NewWebController(userSvc, totpSvc, accountSvc, cfg, root.TemplateFS, oauthHandler)
	if err != nil {
		closeRedis(redisClient)
		return nil, err
	}
	webCtrl.SetAudit(auditLog)
	webCtrl.SetSocial(service.NewSocialService(cfg, userSvc, userRepo, repository.NewSocialRepository(conn), accountSvc, nil))
	oauthHandler.SetTemplates(webCtrl.Templates())
	accountCtrl := controller.NewAccountController(accountSvc, userSvc, sessionSvc, tokenRepo, totpSvc, oauthHandler, webCtrl.Templates(), cfg)
	accountCtrl.SetAudit(auditLog)
	authn := auth.NewMiddleware(tokenRepo, clientRepo, userRepo, dpopSvc)

	var pushHandler *push.Handler
	if cfg.Push.Enabled {
		pushSvc := push.NewService(cfg, conn, dpopSvc)
		pushHandler = push.NewHandler(pushSvc, clientRepo, func(claims jwt.MapClaims) (string, error) {
			key, kid := oidcHandler.GetKeySet().GetRSAKey()
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["typ"] = "push-reg+jwt"
			token.Header["kid"] = kid
			return token.SignedString(key)
		}, func(token *jwt.Token) (any, error) {
			if token.Method == nil || token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
				return nil, fmt.Errorf("unexpected registration token alg")
			}
			key, _ := oidcHandler.GetKeySet().GetRSAKey()
			if key == nil {
				return nil, fmt.Errorf("signing key unavailable")
			}
			return &key.PublicKey, nil
		}, func(r *http.Request) (string, bool) {
			session := oauthHandler.GetSession(r)
			if session == nil || !session.Authenticated {
				return "", false
			}
			return session.UserID, true
		})
		webCtrl.SetPush(pushHandler)
		oauthHandler.SetDeviceLogin(pushSvc)
	}

	var aauthHandler *aauth.Handler
	if cfg.AAuth.Enabled {
		aauthHandler, err = aauth.New(cfg, conn)
		if err != nil {
			closeRedis(redisClient)
			return nil, fmt.Errorf("aauth: %w", err)
		}
	}

	rt := route.NewRouter(mgmtCtrl, webCtrl, oauthHandler, oidcHandler, pushHandler, aauthHandler, accountCtrl, authn, root.OpenAPISpec, root.TemplateFS)
	rt.SetContentSecurityPolicy(service.ContentSecurityPolicy(cfg.Security.BotProtection.Provider))
	return &Built{
		Mux:   rt.GetMux(),
		close: func() { closeRedis(redisClient) },
	}, nil
}

func openCache(cfg *config.Config) (cache.Cache, *redis.Client, error) {
	if cfg.Cache.Provider != "redis" {
		return cache.NewMemory(), nil, nil
	}
	rdb, err := cache.NewClient(cfg.Redis)
	if err != nil {
		return nil, nil, err
	}
	return cache.NewRedis(rdb, cfg.Redis.Prefix), rdb, nil
}

func closeRedis(rdb *redis.Client) {
	if rdb != nil {
		_ = rdb.Close()
	}
}
