package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	"github.com/google/uuid"
)

type captureMail struct {
	mu    sync.Mutex
	texts []string
}

func (m *captureMail) Enabled() bool { return true }

func (m *captureMail) Send(_, _, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.texts = append(m.texts, text)
	return nil
}

func (m *captureMail) last() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.texts) == 0 {
		return ""
	}
	return m.texts[len(m.texts)-1]
}

func (m *captureMail) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.texts)
}

func TestMigratedUserSetsPasswordAfterEmailCode(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "migrate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
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

	migrated, err := users.InsertUser(service.NewUser{
		Username: "ada", Email: "ada@example.com", MigrationPending: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if migrated.HasPassword || !migrated.NeedsMigration() {
		t.Fatalf("pending user = %+v", migrated)
	}
	saml := &models.User{
		ID: uuid.NewString(), Username: "sam", Email: "sam@example.com", CreatedAt: migrated.CreatedAt,
	}
	if err := userRepo.Create(saml); err != nil {
		t.Fatal(err)
	}
	if err := clients.Create(&models.Client{
		ID: "envsync-e2e", Secret: "secret", Name: "e2e",
		GrantTypes: []string{"password"}, Scopes: []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatal(err)
	}

	mux := chi.NewRouter()
	mux.Get("/login", web.HandleLoginPage)
	mux.Post("/login", web.HandleLogin)
	mux.Get("/login/migrate", web.HandleMigrateOTPPage)
	mux.Post("/login/migrate", web.HandleMigrateOTP)
	mux.Get("/login/migrate/password", web.HandleMigratePasswordPage)
	mux.Post("/login/migrate/password", web.HandleMigratePassword)
	mux.Post("/oauth/token", oauthH.HandleToken)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	page := migrateGET(t, client, ts.URL+"/login")
	token := csrfToken(t, page.body)
	login := migratePOST(t, client, ts.URL+"/login", token, url.Values{
		"username": {"ada"},
		"password": {"ignored"},
	})
	if login.StatusCode != http.StatusFound || !strings.Contains(login.location, "/login/migrate") {
		t.Fatalf("login redirect %d %s", login.StatusCode, login.location)
	}
	code := regexp.MustCompile(`\b\d{6}\b`).FindString(mail.last())
	if code == "" {
		t.Fatalf("mail missing code: %q", mail.last())
	}

	otpPage := migrateGET(t, client, ts.URL+login.location)
	otp := migratePOST(t, client, ts.URL+"/login/migrate", csrfToken(t, otpPage.body), url.Values{
		"username": {"ada"},
		"otp":      {code},
	})
	if otp.StatusCode != http.StatusFound || !strings.Contains(otp.location, "/login/migrate/password") {
		t.Fatalf("otp redirect %d %s body %s", otp.StatusCode, otp.location, otp.body)
	}
	passPage := migrateGET(t, client, ts.URL+otp.location)
	if passPage.StatusCode != http.StatusOK {
		t.Fatalf("password page %d %s", passPage.StatusCode, passPage.body)
	}
	done := migratePOST(t, client, ts.URL+"/login/migrate/password", csrfToken(t, passPage.body), url.Values{
		"password":         {"Correct-horse-1"},
		"password_confirm": {"Correct-horse-1"},
	})
	if done.StatusCode != http.StatusFound {
		t.Fatalf("password submit %d %s", done.StatusCode, done.body)
	}
	if _, err := users.Authenticate("ada", "Correct-horse-1"); err != nil {
		t.Fatal(err)
	}
	stored, err := users.GetUser(migrated.ID)
	if err != nil || stored.MigrationPending || !stored.HasPassword {
		t.Fatalf("stored = %+v err %v", stored, err)
	}

	before := mail.count()
	samlPage := migrateGET(t, client, ts.URL+"/login")
	samlLogin := migratePOST(t, client, ts.URL+"/login", csrfToken(t, samlPage.body), url.Values{
		"username": {"sam"},
		"password": {"anything"},
	})
	if samlLogin.StatusCode != http.StatusOK || !strings.Contains(samlLogin.body, "Invalid credentials") {
		t.Fatalf("saml login %d %s", samlLogin.StatusCode, samlLogin.body)
	}
	if mail.count() != before {
		t.Fatalf("saml login sent mail, count %d", mail.count())
	}

	before = mail.count()
	// ada already has a password. A second pending user proves the grant does not send mail.
	if _, err := users.InsertUser(service.NewUser{Username: "bea", Email: "bea@example.com", MigrationPending: true}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"password"},
		"username":   {"bea"},
		"password":   {"nope"},
		"scope":      {"openid"},
	}.Encode()))
	req.SetBasicAuth("envsync-e2e", "secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]string
	_ = json.Unmarshal(raw, &body)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "migration_required" {
		t.Fatalf("grant %d %s", resp.StatusCode, raw)
	}
	if mail.count() != before {
		t.Fatal("password grant sent mail")
	}
}

type migratePage struct {
	StatusCode int
	body       string
	location   string
}

func migrateGET(t *testing.T, client *http.Client, raw string) migratePage {
	t.Helper()
	resp, err := client.Get(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return migratePage{StatusCode: resp.StatusCode, body: string(body), location: resp.Header.Get("Location")}
}

func migratePOST(t *testing.T, client *http.Client, raw, token string, form url.Values) migratePage {
	t.Helper()
	form.Set("csrf_token", token)
	resp, err := client.PostForm(raw, form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return migratePage{StatusCode: resp.StatusCode, body: string(body), location: resp.Header.Get("Location")}
}
