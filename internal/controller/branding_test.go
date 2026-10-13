package controller

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	root "github.com/bravo68web/oauth-impl"
	"github.com/bravo68web/oauth-impl/internal/branding"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
)

func TestOverlayReplacesLoginOnly(t *testing.T) {
	dir := t.TempDir()
	body := `<!DOCTYPE html><html><body><h1>Acme Sign In</h1><form method="POST" action="/login"><input name="username"><input name="password"></form></body></html>`
	if err := os.WriteFile(filepath.Join(dir, "login.html"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tmpl, err := ParseTemplates(root.TemplateFS, dir)
	if err != nil {
		t.Fatal(err)
	}
	login := executePage(t, tmpl, "login.html", config.DefaultConfig(), "Login", "Sign In")
	if !strings.Contains(login, "Acme Sign In") || !strings.Contains(login, `name="username"`) {
		t.Fatalf("login overlay = %s", login)
	}
	register := executePage(t, tmpl, "register.html", config.DefaultConfig(), "Register", "Create Account")
	if !strings.Contains(register, "Create your account") || strings.Contains(register, "Acme Sign In") {
		t.Fatalf("register = %s", register)
	}
}

func TestMissingTemplateDir(t *testing.T) {
	_, err := ParseTemplates(root.TemplateFS, filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected missing templates dir to fail")
	}
}

func TestLoginHidesRegisterLink(t *testing.T) {
	cfg := config.DefaultConfig()
	hide := false
	cfg.Branding.ShowRegister = &hide
	cfg.Branding.PrimaryColor = "#123456"
	tmpl, err := ParseTemplates(root.TemplateFS, "")
	if err != nil {
		t.Fatal(err)
	}
	login := executePage(t, tmpl, "login.html", cfg, "Login", "Ignored")
	if strings.Contains(login, "Create an account") {
		t.Fatalf("register link still present: %s", login)
	}
	if !strings.Contains(login, "Forgot password") {
		t.Fatal("forgot link missing")
	}
	if !strings.Contains(login, "#123456") || !strings.Contains(login, "Sign In") {
		t.Fatalf("login = %s", login)
	}
	if !strings.Contains(login, "Continue to Example App") {
		t.Fatal("client name missing")
	}
	if !strings.Contains(login, `name="password"`) || !strings.Contains(login, `name="client_id"`) {
		t.Fatal("login fields missing")
	}
	register := executePage(t, tmpl, "register.html", cfg, "Register", "Create Account")
	if !strings.Contains(register, `action="/register"`) || !strings.Contains(register, "Create your account") {
		t.Fatalf("register page = %s", register)
	}
}

func TestOrganizationMarkUsesLogoOrInitial(t *testing.T) {
	tmpl, err := ParseTemplates(root.TemplateFS, "")
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]any{
		"Username": "ada",
		"Orgs": []*models.Organization{
			{Name: "Field Notes", Slug: "field-notes"},
			{Name: "Archive", Slug: "archive", LogoURL: "https://cdn.example/archive.png"},
		},
	}
	branding.Prepare(config.DefaultConfig()).Apply(data, "Organization", "Choose an organization", "")
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "organization.html", data); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	if !strings.Contains(body, ">F<") || !strings.Contains(body, "https://cdn.example/archive.png") {
		t.Fatalf("org marks = %s", body)
	}
	if strings.Contains(body, ">A<") {
		t.Fatal("letter mark replaced the logo")
	}
}

func TestBrandSceneStaysInsideTheCard(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Branding.LogoFile = "mark.png"
	cfg.Branding.BackgroundFile = "scene.jpg"
	cfg.Branding.FooterText = "Northwind"
	tmpl, err := ParseTemplates(root.TemplateFS, "")
	if err != nil {
		t.Fatal(err)
	}
	login := executePage(t, tmpl, "login.html", cfg, "Login", "Sign In")
	logo := strings.Index(login, `alt="OAuth Server"`)
	title := strings.Index(login, "Continue to Example App")
	signup := strings.Index(login, "Sign up")
	footer := strings.Index(login, "Northwind")
	section := strings.Index(login, "</section>")
	if !strings.Contains(login, `/branding/assets/scene.jpg`) {
		t.Fatal("background image missing")
	}
	if logo < 0 || title < 0 || logo > title {
		t.Fatal("logo is not above the title")
	}
	if strings.Contains(login, `class="product"`) {
		t.Fatal("product name is shown next to the logo")
	}
	if signup < 0 || footer < 0 || section < 0 || signup > section || footer > section {
		t.Fatal("sign up or footer sits outside the card")
	}
}

func executePage(t *testing.T, tmpl *template.Template, name string, cfg *config.Config, title, heading string) string {
	t.Helper()
	data := map[string]any{}
	theme := branding.Prepare(cfg)
	if name == "login.html" {
		heading = theme.LoginTitle()
	}
	theme.Apply(data, title, heading, "Example App")
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
