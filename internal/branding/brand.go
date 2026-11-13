package branding

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// View is the template value at .Brand. Colors are hex only.
type View struct {
	ProductName     string
	PageTitle       string
	Heading         string
	UsernameLabel   string
	PasswordLabel   string
	SubmitLabel     string
	LogoURL         string
	FaviconURL      string
	BackgroundURL   string
	PrimaryColor    string
	BackgroundColor string
	TextColor       string
	FooterText      string
	SupportURL      string
	PrivacyURL      string
	TermsURL        string
	ShowRegister    bool
	Autocomplete    string
	ShowForgot      bool
	CustomCSS       bool
	ClientName      string
}

// Theme is the branding snapshot taken at startup.
type Theme struct {
	view       View
	loginTitle string
}

// Prepare reads branding from cfg. A nil config uses the built-in defaults.
// custom.css is detected once; adding the file later needs a restart.
func Prepare(cfg *config.Config) Theme {
	defer telemetry.Step("branding.Prepare")()
	if cfg != nil {
		cfg.Normalize()
	}
	b := config.DefaultConfig().Branding
	if cfg != nil {
		b = cfg.Branding
	}
	primary := safeColor(b.PrimaryColor, "#0066ff")
	view := View{
		ProductName:     b.ProductName,
		UsernameLabel:   usernameLabel(cfg, b.UsernameLabel),
		PasswordLabel:   b.PasswordLabel,
		SubmitLabel:     b.SubmitLabel,
		LogoURL:         assetURL(b.LogoFile),
		FaviconURL:      assetURL(b.FaviconFile),
		BackgroundURL:   assetURL(b.BackgroundFile),
		PrimaryColor:    primary,
		BackgroundColor: safeColor(b.BackgroundColor, ""),
		TextColor:       safeColor(b.TextColor, ""),
		FooterText:      b.FooterText,
		SupportURL:      b.SupportURL,
		PrivacyURL:      b.PrivacyURL,
		TermsURL:        b.TermsURL,
		ShowRegister:    (b.ShowRegister == nil || *b.ShowRegister) && (cfg == nil || !cfg.Security.DisableRegistration),
		Autocomplete:    loginAutocomplete(cfg),
		ShowForgot:      b.ShowForgotPassword == nil || *b.ShowForgotPassword,
		CustomCSS:       b.AssetsDir != "" && AssetExists(b.AssetsDir, "custom.css"),
	}
	title := b.LoginTitle
	if title == "" {
		title = "Sign In"
	}
	return Theme{view: view, loginTitle: title}
}

func usernameLabel(cfg *config.Config, label string) string {
	defer telemetry.Step("branding.usernameLabel")()
	if cfg != nil && cfg.Security.LoginIdentifier == "email" && (label == "" || label == "Username") {
		return "Email"
	}
	if label == "" {
		return "Username"
	}
	return label
}

func loginAutocomplete(cfg *config.Config) string {
	defer telemetry.Step("branding.loginAutocomplete")()
	if cfg != nil && cfg.Security.LoginIdentifier == "email" {
		return "email"
	}
	return "username"
}

// LoginTitle is the login page heading after defaults are applied.
// Snapshot is the public branding view. It has no secrets.
func (t Theme) Snapshot() View {
	return t.view
}

func (t Theme) LoginTitle() string {
	defer telemetry.Step("branding.Theme.LoginTitle")()
	if t.loginTitle == "" {
		return "Sign In"
	}
	return t.loginTitle
}

// Apply copies the startup theme onto data["Brand"].
func (t Theme) Apply(data map[string]any, pageTitle, heading, clientName string) {
	defer telemetry.Step("branding.Theme.Apply")()
	if data == nil {
		return
	}
	base := t
	if base.view.ProductName == "" {
		base = Prepare(nil)
	}
	v := base.view
	v.PageTitle = pageTitle
	v.Heading = heading
	v.ClientName = clientName
	data["Brand"] = v
}

func safeColor(value, fallback string) string {
	defer telemetry.Step("branding.safeColor")()
	if value == "" {
		return fallback
	}
	if !configColorOK(value) {
		return fallback
	}
	return value
}

func configColorOK(value string) bool {
	defer telemetry.Step("branding.configColorOK")()
	if (len(value) != 4 && len(value) != 7) || value[0] != '#' {
		return false
	}
	for _, c := range value[1:] {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func assetURL(name string) string {
	defer telemetry.Step("branding.assetURL")()
	if !safeAssetName(name) || config.BrandAssetType(name) == "" {
		return ""
	}
	return "/branding/assets/" + url.PathEscape(name)
}

func safeAssetName(name string) bool {
	defer telemetry.Step("branding.safeAssetName")()
	return name != "" && name != "." && name != ".." && name == filepath.Base(name) && !strings.ContainsAny(name, `/\`)
}
