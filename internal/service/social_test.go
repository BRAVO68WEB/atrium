package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/social"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/bravo68web/atrium/pkg/passhash"
)

func TestSocialLoginCreatesThenReuses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.Form.Get("code") == "" || r.Form.Get("code_verifier") == "" {
				http.Error(w, "bad code", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "no token", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub": "user-1", "email": "ada@example.com", "email_verified": true,
				"preferred_username": "ada", "name": "Ada Lovelace",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	svc, users, repo := newSocialTest(t, upstream, config.DefaultConfig())
	first, state := completeSocial(t, svc, "good-code")
	if first.User.Username != "ada" || !first.User.EmailVerified || first.User.GivenName != "Ada" {
		t.Fatalf("user = %+v", first.User)
	}
	if _, err := svc.Complete(context.Background(), "acme", "good-code", state); err == nil {
		t.Fatal("reused state was accepted")
	}
	second, _ := completeSocial(t, svc, "good-code")
	if second.User.ID != first.User.ID {
		t.Fatal("second login created another user")
	}
	list, err := users.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("users = %d", len(list))
	}
	if _, err := repo.FindIdentity("acme", "user-1"); err != nil {
		t.Fatal(err)
	}
}

func TestSocialRegistrationFlags(t *testing.T) {
	upstream := socialUserInfoServer(t)
	defer upstream.Close()
	cfg := config.DefaultConfig()
	cfg.Security.DisableSocialRegistration = true
	svc, users, _ := newSocialTest(t, upstream, cfg)
	if _, _, err := beginAndComplete(t, svc, "code-1"); err != ErrSocialRegistrationDisabled {
		t.Fatalf("err = %v", err)
	}
	list, err := users.ListUsers()
	if err != nil || len(list) != 0 {
		t.Fatalf("users=%v err=%v", list, err)
	}

	cfg.Security.DisableSocialRegistration = false
	cfg.Security.DisableRegistration = true
	svc, _, _ = newSocialTest(t, upstream, cfg)
	if _, _, err := beginAndComplete(t, svc, "code-2"); err != ErrSocialRegistrationDisabled {
		t.Fatalf("disable_registration err = %v", err)
	}

	cfg = config.DefaultConfig()
	cfg.Security.DisableSocialRegistration = true
	svc, users, repo := newSocialTest(t, upstream, cfg)
	existing, err := users.CreateUser("ada", "correct horse", "ada@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.InsertIdentity("acme", "user-1", existing.ID, existing.Email, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _, err := beginAndComplete(t, svc, "code-3")
	if err != nil {
		t.Fatal(err)
	}
	if got.User.ID != existing.ID {
		t.Fatal("linked identity did not sign in")
	}
}

func TestSocialEmailDoesNotAttach(t *testing.T) {
	upstream := socialUserInfoServer(t)
	defer upstream.Close()
	svc, users, repo := newSocialTest(t, upstream, config.DefaultConfig())
	if _, err := users.CreateUser("local", "correct horse", "ada@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := beginAndComplete(t, svc, "code"); err != ErrSocialEmailInUse {
		t.Fatalf("err = %v", err)
	}
	if _, err := repo.FindIdentity("acme", "user-1"); err == nil {
		t.Fatal("identity was linked to the existing email")
	}
}

func newSocialTest(t *testing.T, upstream *httptest.Server, cfg *config.Config) (*SocialService, *UserService, *repository.SocialRepository) {
	t.Helper()
	db := testpg.Open(t)
	conn := db
	cfg.Security.Issuer = "http://localhost:8080"
	cfg.Social.Providers = []config.SocialProvider{{
		ID: "acme", Type: "oauth2", Enabled: true, ClientID: "cid", ClientSecret: "sec",
		AuthorizationEndpoint: upstream.URL + "/authorize",
		TokenEndpoint:         upstream.URL + "/token",
		UserinfoEndpoint:      upstream.URL + "/userinfo",
	}}
	users := NewUserService(repository.NewUserRepository(conn), nil, &cfg.Security, passhash.Bcrypt(bcrypt.MinCost))
	repo := repository.NewSocialRepository(conn)
	return NewSocialService(cfg, users, repository.NewUserRepository(conn), repo, nil, social.NewClient(upstream.Client())), users, repo
}

func socialUserInfoServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "user-1", "email": "ada@example.com", "email_verified": true, "preferred_username": "ada",
		})
	}))
}

func completeSocial(t *testing.T, svc *SocialService, code string) (SocialResult, string) {
	t.Helper()
	result, state, err := beginAndComplete(t, svc, code)
	if err != nil {
		t.Fatal(err)
	}
	if result.User == nil {
		t.Fatal("missing user")
	}
	return result, state
}

func beginAndComplete(t *testing.T, svc *SocialService, code string) (SocialResult, string, error) {
	t.Helper()
	authURL, err := svc.Begin(context.Background(), "acme", map[string]string{"client_id": "app", "next": "/oauth/authorize"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	state := u.Query().Get("state")
	result, err := svc.Complete(context.Background(), "acme", code, state)
	if err != nil {
		return result, state, err
	}
	if result.Params["client_id"] != "app" || result.Params["next"] != "/oauth/authorize" {
		t.Fatalf("params = %+v", result.Params)
	}
	return result, state, nil
}
