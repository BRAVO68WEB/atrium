package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bravo68web/oauth-impl/internal/app"
	"github.com/bravo68web/oauth-impl/internal/cache"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/log"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/bravo68web/oauth-impl/internal/version"
	"github.com/redis/go-redis/v9"
)

func loadRuntimeConfig(flagPath string) (*config.Config, error) {
	path := flagPath
	if path == "" {
		_, err := os.Stat("config.yaml")
		switch {
		case err == nil:
			path = "config.yaml"
		case os.IsNotExist(err):
			log.Info("no config file found; using built-in defaults")
			return config.DefaultConfig(), nil
		default:
			return nil, fmt.Errorf("stat config.yaml: %w", err)
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	log.Setup(cfg.Log.Format)
	log.Info("loaded config", "path", path)
	return cfg, nil
}

var errVersion = errors.New("version")

type serverOptions struct {
	configPath string
	port       int
	dbPath     string
}

func parseArgs(args []string, out io.Writer) (serverOptions, error) {
	fs := flag.NewFlagSet("oauth-server", flag.ContinueOnError)
	fs.SetOutput(out)
	var opt serverOptions
	var showVersion bool
	fs.StringVar(&opt.configPath, "config", "", "Path to config file")
	fs.IntVar(&opt.port, "port", 0, "Server port (overrides config)")
	fs.StringVar(&opt.dbPath, "db", "", "Database path (overrides config)")
	fs.BoolVar(&showVersion, "version", false, "Print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "Usage: oauth-server [flags]\n\n")
		_, _ = fmt.Fprintf(out, "oauth-server is the OAuth and OIDC server.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return serverOptions{}, err
	}
	if showVersion {
		_, _ = fmt.Fprintf(out, "oauth-server %s\n", version.Line())
		return serverOptions{}, errVersion
	}
	return opt, nil
}

func main() {
	opt, err := parseArgs(os.Args[1:], os.Stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) || errors.Is(err, errVersion) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	cfg, err := loadRuntimeConfig(opt.configPath)
	if err != nil {
		log.Fatal("failed to load config", "err", err)
	}

	cfg.Normalize()
	shutdownTrace, err := telemetry.Setup(context.Background(), &cfg.Telemetry)
	if err != nil {
		log.Fatal("telemetry", "err", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), telemetry.ShutdownTimeout)
		defer cancel()
		if err := shutdownTrace(ctx); err != nil {
			log.Error("telemetry shutdown", "err", err)
		}
	}()

	if opt.port > 0 {
		cfg.Server.Port = opt.port
	}
	if opt.dbPath != "" {
		cfg.Database.Path = opt.dbPath
	}

	if err := os.MkdirAll(".", 0755); err != nil {
		log.Fatal("failed to create directories", "err", err)
	}

	// Database
	db, err := database.Open(cfg)
	if err != nil {
		log.Fatal("failed to initialize database", "err", err)
	}
	defer func() { _ = db.Close() }()

	if cfg.Database.Migrations {
		if err := db.Migrate(); err != nil {
			log.Fatal("failed to run migrations", "err", err)
		}
		log.Info("database migrations completed")
	}

	var rdb *redis.Client
	if cfg.Queue.Type == "redis" || cfg.Cache.Provider == "redis" {
		rdb, err = cache.NewClient(cfg.Redis)
		if err != nil {
			log.Fatal("redis", "err", err)
		}
		defer func() { _ = rdb.Close() }()
	}
	if cfg.Queue.Type == "redis" && cfg.Cache.Provider != "redis" {
		log.Warn("queue.type is redis and cache.provider is memory; DPoP, XAA, CIMD, and sector state stay on this process")
	}
	var q queue.Queue
	switch cfg.Queue.Type {
	case "", "memory":
		q = queue.NewMemoryQueue(cfg.Queue.MaxPending)
	case "redis":
		q = queue.NewRedis(rdb, cfg.Redis.Prefix, cfg.Queue.MaxPending)
	default:
		log.Fatal("queue.type must be memory or redis")
	}

	built, err := app.Build(cfg, db, q, rdb)
	if err != nil {
		log.Fatal("server", "err", err)
	}
	defer built.Close()

	// Build TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	if cfg.Server.TLS.Enabled && cfg.Server.TLS.ClientCA != "" {
		caCert, err := os.ReadFile(cfg.Server.TLS.ClientCA)
		if err != nil {
			log.Fatal("failed to read client CA", "err", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool

		switch cfg.Server.TLS.ClientAuth {
		case "require_and_verify":
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		case "require":
			tlsConfig.ClientAuth = tls.RequireAnyClientCert
		case "request":
			tlsConfig.ClientAuth = tls.RequestClientCert
		default:
			tlsConfig.ClientAuth = tls.NoClientCert
		}
	}

	// HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      built.Mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    tlsConfig,
	}

	protocol := "http"
	if cfg.Server.TLS.Enabled {
		protocol = "https"
	}

	fmt.Printf(`
╔══════════════════════════════════════════════════════════════╗
║                    OAuth Implementation Server               ║
╠══════════════════════════════════════════════════════════════╣
║  Server:      %s://%s:%-25s ║
║  Version:     %-46s ║
║  Database:    %-46s ║
║  Queue:       %-46s ║
║  MFA:         %-46s ║
║  TLS:         %-46s ║
║  mTLS:        %-46s ║
║  DPoP:        %-46s ║
╚══════════════════════════════════════════════════════════════╝

Endpoints:
  OAuth 2.0:
    POST /oauth/authorize     - Authorization endpoint
    POST /oauth/token         - Token endpoint
    POST /oauth/revoke        - Token revocation (RFC 7009)
    POST /oauth/introspect    - Token introspection (RFC 7662)
    POST /oauth/register      - Dynamic client registration (RFC 7591)
    POST /oauth/device        - Device authorization (RFC 8628)
    POST /oauth/par           - Pushed authorization requests (RFC 9126)
    POST /oauth/bc-authorize  - CIBA backchannel authentication

  OIDC:
    GET  /.well-known/openid-configuration
    GET  /.well-known/oauth-authorization-server
    GET  /oidc/userinfo
    GET  /oidc/jwks

  Web:
    GET  /login               - Login page
    GET  /register            - Registration page
    GET  /consent             - OIDC consent screen
    GET  /profile             - Signed-in account and application access
    GET  /mfa/enroll          - MFA enrollment with QR code

  API Documentation:
    GET  /docs                - Scalar API docs UI
    GET  /openapi             - OpenAPI spec (JSON)
    GET  /docs/openapi.yaml   - OpenAPI spec (YAML)

  Management API:
    GET/POST   /api/clients
    GET/PUT/DELETE /api/clients/{id}
    GET/POST   /api/users
    GET        /api/users/{id}
    GET        /api/tokens
    POST       /api/tokens/{token}/revoke
    GET        /api/ciba/pending
    POST       /api/ciba/{id}/approve
    POST       /api/ciba/{id}/deny

  Health:
    GET  /health
    GET  /version

`, protocol, cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port),
		version.Current().Version,
		cfg.Database.Path, cfg.Queue.Type, mfaStatus(cfg),
		tlsStatus(cfg), mtlsStatus(cfg), dpopStatus(cfg))

	// Start server
	go func() {
		log.Info("starting OAuth server", "version", version.Line(), "url", protocol+"://"+net.JoinHostPort(cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port)))
		if cfg.Server.TLS.Enabled {
			if err := httpServer.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatal("server failed", "err", err)
			}
		} else {
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal("server failed", "err", err)
			}
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server")
	_ = httpServer.Close()
}

func mfaStatus(cfg *config.Config) string {
	if cfg.Security.MFA.Required {
		return "required (all users)"
	}
	if cfg.Security.MFA.Enabled {
		return "enabled (optional)"
	}
	return "disabled"
}

func tlsStatus(cfg *config.Config) string {
	if !cfg.Server.TLS.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled (cert: %s)", cfg.Server.TLS.CertFile)
}

func mtlsStatus(cfg *config.Config) string {
	if !cfg.Security.MTLS.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled (client_auth: %s)", cfg.Server.TLS.ClientAuth)
}

func dpopStatus(cfg *config.Config) string {
	if !cfg.Security.DPoP.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled (nonce_required: %v)", cfg.Security.DPoP.NonceRequired)
}
