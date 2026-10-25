package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
)

func TestPasswordPolicyOnWriteNotLogin(t *testing.T) {
	h := scriptHasher{
		hashFn: func(password string) (string, error) { return "hashed:" + password, nil },
		verifyFn: func(encoded, password string) error {
			if encoded != "hashed:"+password {
				return errors.New("mismatch")
			}
			return nil
		},
	}
	svc, repo := newTestUserService(t, h)
	svc.cfg.Password.MinLength = 12

	if _, err := svc.CreateUser("ada", "short-pass", "", ""); err == nil {
		t.Fatal("expected short password to be rejected")
	} else {
		var pe *PasswordError
		if !errors.As(err, &pe) {
			t.Fatalf("error type %T", err)
		}
	}
	user, err := svc.CreateUser("ada", "long-enough-pass", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdatePasswordHash(user.ID, "hashed:short"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate("ada", "short"); err != nil {
		t.Fatalf("old short hash should still log in: %v", err)
	}
}

func TestFetchRejectsLoopbackAndRedirects(t *testing.T) {
	if err := ValidateFetchTarget(&config.Config{}, "http://127.0.0.1/hook"); err == nil {
		t.Fatal("expected loopback http to be rejected")
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, srvRedirect(r), http.StatusFound)
	}))
	defer srv.Close()
	cfg := config.DefaultConfig()
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1"}
	_, status, err := FetchSafe(context.Background(), cfg, http.MethodGet, srv.URL+"/jwks", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusFound {
		t.Fatalf("status %d, redirects must not be followed", status)
	}
	if hits != 1 {
		t.Fatalf("hits %d", hits)
	}
}

func srvRedirect(r *http.Request) string {
	return "http://" + r.Host + "/followed"
}

func TestBotToken(t *testing.T) {
	bot := config.BotProtectionConfig{Provider: "turnstile", SiteKey: "site", SecretKey: "secret"}
	if err := VerifyBot(context.Background(), bot, "", "127.0.0.1:1"); err == nil {
		t.Fatal("missing token should fail")
	}
	prev := BotPoster
	BotPoster = func(ctx context.Context, provider, secret, token, remoteIP string) error {
		if provider != "turnstile" || secret != "secret" || token != "ok" {
			return errors.New("unexpected")
		}
		return nil
	}
	defer func() { BotPoster = prev }()
	if err := VerifyBot(context.Background(), bot, "ok", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
}

func TestAuditOmitsSecrets(t *testing.T) {
	db := testpg.Open(t)
	log := NewAuditLog(repository.NewAuditRepository(db))
	log.Write("client", "mgmt", "client.create", "client", "app", nil, map[string]any{
		"name": "App", "secret": "s3cret", "client_secret": "nope",
	})
	rows, err := log.List("client.create", "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows %d", len(rows))
	}
	if rows[0].Metadata["name"] != "App" {
		t.Fatalf("metadata %+v", rows[0].Metadata)
	}
	if _, ok := rows[0].Metadata["secret"]; ok {
		t.Fatal("secret leaked")
	}
	if _, ok := rows[0].Metadata["client_secret"]; ok {
		t.Fatal("client secret leaked")
	}
}
