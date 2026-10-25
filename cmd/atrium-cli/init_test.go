package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/hashalgo"
)

func TestInitWritesConfigAndHasher(t *testing.T) {
	dir := t.TempDir()
	result, err := runInit(initOptions{Dir: dir, WithMFA: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.HasherMessage, "written") {
		t.Fatalf("message %q", result.HasherMessage)
	}

	loaded, err := config.Load(result.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Security.HashAlgo != hashalgo.CanonicalRel {
		t.Fatalf("hash_algo = %q", loaded.Security.HashAlgo)
	}
	if !loaded.Security.MFA.Enabled || !loaded.Security.MFA.Required {
		t.Fatal("expected MFA enabled and required")
	}
	if loaded.Server.Port != 8080 {
		t.Fatalf("port = %d", loaded.Server.Port)
	}

	dest := filepath.Join(dir, filepath.FromSlash(hashalgo.CanonicalRel))
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(hashalgo.BcryptTemplate())) {
		t.Fatal("hasher file is not the bcrypt template")
	}

	modified := append(append([]byte{}, got...), []byte("// operator\n")...)
	if err := os.WriteFile(dest, modified, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runInit(initOptions{Dir: dir, Hash: "argon2id"}); err == nil {
		t.Fatal("expected existing config error")
	}
	after, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, modified) {
		t.Fatal("second init overwrote algo.go")
	}
}

func TestInitKeepsCustomHasherWithoutForce(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, filepath.FromSlash(hashalgo.CanonicalRel))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	custom := []byte(hashalgo.BcryptTemplate() + "// operator\n")
	if err := os.WriteFile(dest, custom, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := runInit(initOptions{Dir: dir, Hash: "argon2id"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.HasherMessage, "Kept existing") {
		t.Fatalf("message %q", result.HasherMessage)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, custom) {
		t.Fatal("custom hasher was replaced")
	}
}

func TestInitForceArgon2(t *testing.T) {
	dir := t.TempDir()
	if _, err := runInit(initOptions{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := runInit(initOptions{Dir: dir, Hash: "argon2id", Force: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(hashalgo.CanonicalRel)))
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !strings.Contains(text, "Argon2id") || !strings.Contains(text, "Fallback") {
		t.Fatalf("argon2 template not written:\n%s", text)
	}
}

func TestInitRejectsExtraExport(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.go")
	body := hashalgo.BcryptTemplate() + "\nfunc Extra() {}\n"
	if err := os.WriteFile(custom, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := runInit(initOptions{Dir: dir, HashAlgo: "custom.go"})
	if err == nil || !strings.Contains(err.Error(), "exactly one function") {
		t.Fatalf("error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, filepath.FromSlash(hashalgo.CanonicalRel))); !os.IsNotExist(statErr) {
		t.Fatal("hasher file was written")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(statErr) {
		t.Fatal("config file was written")
	}
}
