package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRuntimeConfigWithoutAFileUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg, err := loadRuntimeConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Port == 0 {
		t.Fatal("expected the built-in port")
	}
}

func TestLoadRuntimeConfigReadsTheNamedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  port: 9091\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRuntimeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Port != 9091 {
		t.Fatalf("port %d", cfg.Server.Port)
	}
}

func TestLoadRuntimeConfigRejectsAMissingPath(t *testing.T) {
	_, err := loadRuntimeConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected a missing file to fail")
	}
}
