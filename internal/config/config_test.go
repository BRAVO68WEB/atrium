package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Port != 8080 {
		t.Fatalf("port = %d", cfg.Server.Port)
	}
	if cfg.Security.HashAlgo != "internal/hashalgo/algo.go" {
		t.Fatalf("hash_algo = %q", cfg.Security.HashAlgo)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := DefaultConfig()
	cfg.Security.MFA.Enabled = true
	cfg.Security.MFA.Required = true
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Security.AccessTokenLifetime != cfg.Security.AccessTokenLifetime {
		t.Fatalf("access token lifetime %s", loaded.Security.AccessTokenLifetime)
	}
	if !loaded.Security.MFA.Enabled || !loaded.Security.MFA.Required {
		t.Fatal("mfa flags were not saved")
	}
	if loaded.Security.HashAlgo != cfg.Security.HashAlgo {
		t.Fatalf("hash_algo = %q", loaded.Security.HashAlgo)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if loaded.Branding.ProductName != "OAuth Server" || loaded.Branding.PrimaryColor != "#0066ff" {
		t.Fatalf("branding = %+v", loaded.Branding)
	}
	if loaded.Branding.ShowRegister == nil || !*loaded.Branding.ShowRegister {
		t.Fatal("show_register default was not saved")
	}
}

func TestBrandingNormalizeDefaults(t *testing.T) {
	var cfg Config
	cfg.Normalize()
	if cfg.Branding.PrimaryColor != "#0066ff" {
		t.Fatalf("primary = %q", cfg.Branding.PrimaryColor)
	}
	if cfg.Branding.ProductName != "OAuth Server" || cfg.Branding.LoginTitle != "Sign In" {
		t.Fatalf("copy = %+v", cfg.Branding)
	}
	if cfg.Branding.ShowRegister == nil || !*cfg.Branding.ShowRegister {
		t.Fatal("missing show_register did not default to true")
	}
	if cfg.Branding.ShowForgotPassword == nil || !*cfg.Branding.ShowForgotPassword {
		t.Fatal("missing show_forgot_password did not default to true")
	}
}

func TestBrandingExplicitFalseStaysFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := []byte("branding:\n  show_register: false\n  show_forgot_password: false\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Branding.ShowRegister == nil || *cfg.Branding.ShowRegister {
		t.Fatal("show_register was not false")
	}
	if cfg.Branding.ShowForgotPassword == nil || *cfg.Branding.ShowForgotPassword {
		t.Fatal("show_forgot_password was not false")
	}
}

func TestSocialValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Social.Providers = []SocialProvider{{
		ID: "google", Type: "google", Enabled: true, ClientID: "cid",
	}}
	if err := ValidateSocial(cfg); err == nil {
		t.Fatal("expected missing secret to fail")
	}
	cfg.Social.Providers = []SocialProvider{{
		ID: "google", Type: "nope", Enabled: false,
	}}
	if err := ValidateSocial(cfg); err == nil {
		t.Fatal("expected unknown type to fail")
	}
	cfg.Social.Providers = []SocialProvider{
		{ID: "google", Type: "google", Enabled: false},
		{ID: "google", Type: "github", Enabled: false},
	}
	if err := ValidateSocial(cfg); err == nil {
		t.Fatal("expected duplicate id to fail")
	}
	cfg.Social.Providers = []SocialProvider{{
		ID: "acme", Type: "oauth2", Enabled: true, ClientID: "cid", ClientSecret: "sec",
		AuthorizationEndpoint: "https://id.example/auth",
		TokenEndpoint:         "https://id.example/token",
		UserinfoEndpoint:      "https://id.example/userinfo",
	}}
	if err := ValidateSocial(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Notify.Type = "rabbitmq"
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected rabbitmq without a url to fail")
	}
	cfg.Notify.RabbitMQ.URL = "amqp://localhost"
	if err := ValidatePlatform(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Notify.Type = "redis"
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected redis without an address to fail")
	}
}

func TestBrandingRejectsBadValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Branding.PrimaryColor = "red"
	if err := ValidateBranding(cfg); err == nil {
		t.Fatal("expected red to fail")
	}
	cfg = DefaultConfig()
	cfg.Branding.PrimaryColor = "#0066ff; }"
	if err := ValidateBranding(cfg); err == nil {
		t.Fatal("expected css breakout to fail")
	}
	cfg = DefaultConfig()
	cfg.Branding.PrimaryColor = "#abc"
	if err := ValidateBranding(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Branding.BackgroundColor = "#AABBCC"
	if err := ValidateBranding(cfg); err != nil {
		t.Fatal(err)
	}
	cfg = DefaultConfig()
	cfg.Branding.SupportURL = "javascript:alert(1)"
	if err := ValidateBranding(cfg); err == nil {
		t.Fatal("expected javascript URL to fail")
	}
	cfg = DefaultConfig()
	cfg.Branding.LogoFile = "../config.yaml"
	if err := ValidateBranding(cfg); err == nil {
		t.Fatal("expected logo traversal to fail")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scene.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg = DefaultConfig()
	cfg.Branding.AssetsDir = dir
	cfg.Branding.BackgroundFile = "scene.css"
	if err := ValidateBranding(cfg); err == nil || !strings.Contains(err.Error(), "svg") {
		t.Fatalf("css background error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scene.jpg"), []byte("jpeg"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg = DefaultConfig()
	cfg.Branding.AssetsDir = dir
	cfg.Branding.BackgroundFile = "scene.jpg"
	if err := ValidateBranding(cfg); err != nil {
		t.Fatal(err)
	}
	cfg = DefaultConfig()
	cfg.Branding.Templates = filepath.Join(t.TempDir(), "missing-templates")
	if err := ValidateBranding(cfg); err == nil {
		t.Fatal("expected missing templates dir to fail")
	}
}
