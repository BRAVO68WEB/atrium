package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	root "github.com/bravo68web/atrium"
	"github.com/bravo68web/atrium/internal/branding"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/service"
)

func TestDisableRegistrationBlocksWebSignup(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Security.DisableRegistration = true
	show := true
	cfg.Branding.ShowRegister = &show
	c := &WebController{cfg: cfg, theme: branding.Prepare(cfg)}

	page := httptest.NewRecorder()
	c.HandleRegisterPage(page, httptest.NewRequest(http.MethodGet, "/register", nil))
	if page.Code != http.StatusForbidden || !strings.Contains(page.Body.String(), "Registration is disabled") {
		t.Fatalf("GET /register = %d %s", page.Code, page.Body.String())
	}

	post := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("username=ada&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.HandleRegister(post, req)
	if post.Code != http.StatusForbidden {
		t.Fatalf("POST /register = %d %s", post.Code, post.Body.String())
	}

	tmpl, err := ParseTemplates(root.TemplateFS, "")
	if err != nil {
		t.Fatal(err)
	}
	login := executePage(t, tmpl, "login.html", cfg, "Login", "Sign In")
	if strings.Contains(login, "Create an account") {
		t.Fatal("register link shown while registration is disabled")
	}
}

func TestLoginShowsEnabledSocialProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Social.Providers = []config.SocialProvider{
		{ID: "google", Type: "google", Enabled: true, ClientID: "cid", ClientSecret: "sec"},
		{ID: "github", Type: "github", Enabled: false, ClientID: "cid", ClientSecret: "sec"},
	}
	tmpl, err := ParseTemplates(root.TemplateFS, "")
	if err != nil {
		t.Fatal(err)
	}
	c := &WebController{
		cfg:       cfg,
		templates: tmpl,
		theme:     branding.Prepare(cfg),
		social:    service.NewSocialService(cfg, nil, nil, nil, nil, nil),
	}
	rec := httptest.NewRecorder()
	c.HandleLoginPage(rec, httptest.NewRequest(http.MethodGet, "/login?client_id=app", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `href="/login/social/google?`) {
		t.Fatalf("login = %d %s", rec.Code, body)
	}
	if strings.Contains(body, "/login/social/github") {
		t.Fatal("disabled provider is linked")
	}
	if !strings.Contains(body, "client_id=app") {
		t.Fatal("oauth query was dropped")
	}
}
