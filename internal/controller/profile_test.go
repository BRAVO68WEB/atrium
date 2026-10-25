package controller

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	root "github.com/bravo68web/atrium"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/handlers/oauth"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/pkg/passhash"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

func TestProfileKeepsTheCurrentSessionAndChecksSecrets(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "profile.db"))
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
	logout := service.NewLogoutService(sessions, repository.NewClientRepository(db), nil)
	account := service.NewAccountService(users, userRepo, repository.NewEmailTokenRepository(db), repository.NewLoginEventRepository(db), sessions, tokens, nil, logout, cfg)
	oauthH := oauth.NewHandler(nil, userRepo, tokens, nil, nil, nil, nil, nil, nil, nil, nil, cfg, nil, nil, users, sessions, logout, account)
	web, err := NewWebController(users, totpSvc, account, cfg, root.TemplateFS, oauthH)
	if err != nil {
		t.Fatal(err)
	}
	ctrl := NewAccountController(account, users, sessions, tokens, totpSvc, oauthH, web.Templates(), cfg)

	const password = "Correct-horse-1"
	user, err := users.CreateUser("ada", password, "ada@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := sessions.Start(user.ID, user.Username, "Firefox", "203.0.113.10", true)
	if err != nil {
		t.Fatal(err)
	}

	mux := chi.NewRouter()
	mux.Get("/profile", ctrl.HandleProfile)
	mux.Post("/profile/password", ctrl.HandleProfilePassword)
	mux.Post("/profile/email", ctrl.HandleProfileEmail)
	mux.Post("/profile/mfa", ctrl.HandleProfileMFA)
	mux.Post("/profile/sessions", ctrl.HandleProfileSession)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sign := httptest.NewRecorder()
	oauthH.SetSessionRequest(sign, httptest.NewRequest(http.MethodGet, ts.URL+"/", nil), user.ID, user.Username, true)
	base, _ := url.Parse(ts.URL)
	jar.SetCookies(base, sign.Result().Cookies())

	page := profileGET(t, client, ts.URL+"/profile")
	if !strings.Contains(page.body, "This browser") || !strings.Contains(page.body, "Other browser") {
		t.Fatalf("sessions missing: %s", page.body)
	}
	token := csrfToken(t, page.body)

	bad := profilePOST(t, client, ts.URL+"/profile/password", token, url.Values{
		"current_password": {"nope"},
		"new_password":     {"Correct-horse-2"},
	})
	if bad.StatusCode != http.StatusOK || !strings.Contains(bad.body, "invalid credentials") {
		t.Fatalf("bad password %d %s", bad.StatusCode, bad.body)
	}
	if _, err := users.Authenticate("ada", password); err != nil {
		t.Fatal("old password stopped working")
	}

	self := profilePOST(t, client, ts.URL+"/profile/sessions", token, url.Values{"session_id": {page.sessionID(t)}})
	if self.StatusCode != http.StatusOK || !strings.Contains(self.body, "This browser stays signed in") {
		t.Fatalf("current session %d %s", self.StatusCode, self.body)
	}
	if _, err := sessions.Get(page.sessionID(t)); err != nil {
		t.Fatal("current session was revoked")
	}
	gone := profilePOST(t, client, ts.URL+"/profile/sessions", token, url.Values{"session_id": {other.ID}})
	if gone.StatusCode != http.StatusFound {
		t.Fatalf("other session %d %s", gone.StatusCode, gone.body)
	}
	if _, err := sessions.Get(other.ID); err == nil {
		t.Fatal("other session still active")
	}

	mail := profilePOST(t, client, ts.URL+"/profile/email", token, nil)
	if mail.StatusCode != http.StatusOK || !strings.Contains(mail.body, "SMTP is not configured") {
		t.Fatalf("email %d %s", mail.StatusCode, mail.body)
	}

	enroll, err := totpSvc.EnableMFA(user.ID, user.Username)
	if err != nil {
		t.Fatal(err)
	}
	good, err := totp.GenerateCode(enroll.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := totpSvc.ConfirmMFA(user.ID, good); err != nil {
		t.Fatal(err)
	}
	wrong := profilePOST(t, client, ts.URL+"/profile/mfa", token, url.Values{"code": {"000000"}})
	if wrong.StatusCode != http.StatusOK || !strings.Contains(wrong.body, "Code is wrong") {
		t.Fatalf("mfa reject %d %s", wrong.StatusCode, wrong.body)
	}
	if on, _ := totpSvc.IsMFAEnabled(user.ID); !on {
		t.Fatal("mfa turned off with a bad code")
	}
	again, err := totp.GenerateCode(enroll.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	off := profilePOST(t, client, ts.URL+"/profile/mfa", token, url.Values{"code": {again}})
	if off.StatusCode != http.StatusFound {
		t.Fatalf("mfa off %d %s", off.StatusCode, off.body)
	}
	if on, _ := totpSvc.IsMFAEnabled(user.ID); on {
		t.Fatal("mfa still on")
	}
}

type profilePage struct {
	StatusCode int
	body       string
	cookies    []*http.Cookie
}

func (p profilePage) sessionID(t *testing.T) string {
	t.Helper()
	for _, c := range p.cookies {
		if c.Name == "session_id" {
			return c.Value
		}
	}
	t.Fatal("session cookie missing")
	return ""
}

func profileGET(t *testing.T, client *http.Client, raw string) profilePage {
	t.Helper()
	resp, err := client.Get(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return profilePage{StatusCode: resp.StatusCode, body: string(body), cookies: client.Jar.Cookies(mustURL(raw))}
}

func profilePOST(t *testing.T, client *http.Client, raw, token string, form url.Values) profilePage {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", token)
	resp, err := client.PostForm(raw, form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return profilePage{StatusCode: resp.StatusCode, body: string(body)}
}

func csrfToken(t *testing.T, body string) string {
	t.Helper()
	const needle = `name="csrf_token" value="`
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatalf("csrf missing: %s", body)
	}
	rest := body[i+len(needle):]
	j := strings.Index(rest, `"`)
	return rest[:j]
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
