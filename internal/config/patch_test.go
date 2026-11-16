package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyFileKeepsSecretAndComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := "# keep me\nsmtp:\n  host: mail.example\n  password: super-secret\n  port: 587\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ApplyFile(path, map[string]any{
		"smtp": map[string]any{"host": "other.example"},
		"dashboard": map[string]any{
			"enabled":          true,
			"session_lifetime": "8h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.Contains(text, "super-secret") {
		t.Fatalf("password was dropped:\n%s", text)
	}
	if !strings.Contains(text, "other.example") {
		t.Fatalf("host was not updated:\n%s", text)
	}
	if !strings.Contains(text, "enabled: true") {
		t.Fatalf("dashboard was not added:\n%s", text)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SMTP.Password != "super-secret" || cfg.SMTP.Host != "other.example" || !cfg.Dashboard.Enabled {
		t.Fatalf("reloaded %+v", cfg.SMTP)
	}
}

func TestApplyFileRejectsBadTelemetry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("telemetry:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ApplyFile(path, map[string]any{
		"telemetry": map[string]any{"enabled": true},
	})
	if err == nil || !strings.Contains(err.Error(), "otlp_endpoint") {
		t.Fatalf("err = %v", err)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "enabled: true") {
		t.Fatalf("invalid edit was written:\n%s", got)
	}
}
