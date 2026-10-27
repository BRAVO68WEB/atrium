package controller

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	root "github.com/bravo68web/atrium"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/handlers/oauth"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/pkg/passhash"
	"github.com/go-chi/chi/v5"
)

func TestPasswordlessOTPSignsInWithoutPassword(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "otp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Security.DisablePasswords = true
	cfg.Security.PasswordlessMode = "otp"
	cfg.Normalize()
	userRepo := repository.NewUserRepository(db)
	totpSvc := service.NewTOTPService(userRepo, &cfg.Security.MFA)
	users := service.NewUserService(userRepo, totpSvc, &cfg.Security, passhash.Bcrypt(0))
	sessions := service.NewSessionService(repository.NewSessionRepository(db), cfg.Security.SessionLifetime)
	tokens := repository.NewTokenRepository(db)
	clients := repository.NewClientRepository(db)
	mail := &captureMail{}
	account := service.NewAccountService(users, userRepo, repository.NewEmailTokenRepository(db), repository.NewLoginEventRepository(db), sessions, tokens, mail, nil, cfg)
	oauthH := oauth.NewHandler(clients, userRepo, tokens, nil, nil, nil, nil, nil, nil, nil, nil, cfg, nil, nil, users, sessions, nil, account)
	web, err := NewWebController(users, totpSvc, account, cfg, root.TemplateFS, oauthH)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.InsertUser(service.NewUser{Username: "ada", Email: "ada@example.com", Password: "Correct-horse-1"}); err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(&models.Client{
		ID: "envsync-e2e", Secret: "secret", Name: "e2e",
		GrantTypes: []string{"password"}, Scopes: []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatal(err)
	}
	mux := chi.NewRouter()
	mux.Get("/login", web.HandleLoginPage)
	mux.Post("/login", web.HandleLogin)
	mux.Get("/login/otp", web.HandleLoginOTPPage)
	mux.Post("/login/otp", web.HandleLoginOTP)
	mux.Post("/oauth/token", oauthH.HandleToken)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	page := migrateGET(t, client, ts.URL+"/login")
	if strings.Contains(page.body, `name="password"`) {
		t.Fatalf("password field shown while passwords are disabled: %s", page.body)
	}
	sent := migratePOST(t, client, ts.URL+"/login", csrfToken(t, page.body), url.Values{
		"login_step": {"identifier"},
		"username":   {"ada"},
	})
	if sent.StatusCode != http.StatusFound || !strings.Contains(sent.location, "/login/otp") {
		t.Fatalf("otp redirect %d %s", sent.StatusCode, sent.location)
	}
	code := regexp.MustCompile(`\b\d{6}\b`).FindString(mail.last())
	if code == "" {
		t.Fatalf("mail missing code: %q", mail.last())
	}
	otpPage := migrateGET(t, client, ts.URL+sent.location)
	done := migratePOST(t, client, ts.URL+"/login/otp", csrfToken(t, otpPage.body), url.Values{
		"username": {"ada"},
		"otp":      {code},
	})
	if done.StatusCode != http.StatusFound || !strings.Contains(done.location, "/oauth/authorize") {
		t.Fatalf("sign-in redirect %d %s body %s", done.StatusCode, done.location, done.body)
	}

	codes := mail.containing("Your sign-in code is")
	unknownPage := migrateGET(t, client, ts.URL+"/login")
	unknown := migratePOST(t, client, ts.URL+"/login", csrfToken(t, unknownPage.body), url.Values{
		"username": {"nobody"},
	})
	if unknown.StatusCode != http.StatusFound || !strings.Contains(unknown.location, "/login/otp") || mail.containing("Your sign-in code is") != codes {
		t.Fatalf("unknown user %d %s codes %d", unknown.StatusCode, unknown.location, mail.containing("Your sign-in code is"))
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"Correct-horse-1"},
	}.Encode()))
	req.SetBasicAuth("envsync-e2e", "secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "Passwords are disabled") {
		t.Fatalf("password grant %d %s", resp.StatusCode, body)
	}
}

func TestPasswordlessLinkSignsInOnce(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "link.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Security.DisablePasswords = true
	cfg.Security.PasswordlessMode = "link"
	cfg.Security.Issuer = "http://auth.example"
	cfg.Normalize()
	userRepo := repository.NewUserRepository(db)
	totpSvc := service.NewTOTPService(userRepo, &cfg.Security.MFA)
	users := service.NewUserService(userRepo, totpSvc, &cfg.Security, passhash.Bcrypt(0))
	sessions := service.NewSessionService(repository.NewSessionRepository(db), cfg.Security.SessionLifetime)
	tokens := repository.NewTokenRepository(db)
	mail := &captureMail{}
	account := service.NewAccountService(users, userRepo, repository.NewEmailTokenRepository(db), repository.NewLoginEventRepository(db), sessions, tokens, mail, nil, cfg)
	web, err := NewWebController(users, totpSvc, account, cfg, root.TemplateFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.InsertUser(service.NewUser{Username: "bea", Email: "bea@example.com", Password: "Correct-horse-1"}); err != nil {
		t.Fatal(err)
	}
	mux := chi.NewRouter()
	mux.Get("/login", web.HandleLoginPage)
	mux.Post("/login", web.HandleLogin)
	mux.Get("/login/link", web.HandleLoginLink)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	page := migrateGET(t, client, ts.URL+"/login")
	sent := migratePOST(t, client, ts.URL+"/login", csrfToken(t, page.body), url.Values{"username": {"bea"}})
	if sent.StatusCode != http.StatusOK || !strings.Contains(sent.body, "sign-in link") {
		t.Fatalf("link notice %d %s", sent.StatusCode, sent.body)
	}
	match := regexp.MustCompile(`token=([^&\s]+)`).FindStringSubmatch(mail.last())
	if len(match) != 2 {
		t.Fatalf("mail missing link: %q", mail.last())
	}
	token, err := url.QueryUnescape(match[1])
	if err != nil {
		t.Fatal(err)
	}
	first := migrateGET(t, client, ts.URL+"/login/link?token="+url.QueryEscape(token))
	if first.StatusCode != http.StatusFound || !strings.Contains(first.location, "/oauth/authorize") {
		t.Fatalf("link redirect %d %s body %s", first.StatusCode, first.location, first.body)
	}
	second := migrateGET(t, client, ts.URL+"/login/link?token="+url.QueryEscape(token))
	if second.StatusCode != http.StatusOK || !strings.Contains(second.body, "not valid") {
		t.Fatalf("reused link %d %s", second.StatusCode, second.body)
	}
}
