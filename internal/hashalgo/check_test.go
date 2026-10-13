package hashalgo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bravo68web/oauth-impl/internal/config"
)

func TestDefaultFileMatchesBinary(t *testing.T) {
	path, err := CanonicalFile(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(path); err != nil {
		t.Fatal(err)
	}
	if err := MatchesEmbedded(path); err != nil {
		t.Fatal(err)
	}
	if config.DefaultConfig().Security.HashAlgo != CanonicalRel {
		t.Fatalf("config hash_algo = %q", config.DefaultConfig().Security.HashAlgo)
	}
	h, err := Prepare(".", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if h.ID() != "bcrypt" {
		t.Fatalf("ID = %s", h.ID())
	}
}

func TestMatchesEmbeddedRejectsDrift(t *testing.T) {
	path := filepath.Join(t.TempDir(), "algo.go")
	if err := os.WriteFile(path, []byte(BcryptTemplate()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MatchesEmbedded(path); err == nil {
		t.Fatal("expected drift error")
	}
}

func TestResolveServerPath(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, filepath.FromSlash(CanonicalRel))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte(BcryptTemplate()), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveServerPath(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(dest) {
		t.Fatalf("got %s want %s", got, dest)
	}
	if _, err := ResolveServerPath(dir, "other.go", ""); err == nil {
		t.Fatal("expected HASH_ALGO error")
	}

	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err = ResolveServerPath(sub, "", CanonicalRel)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(dest) {
		t.Fatalf("from subdir got %s want %s", got, dest)
	}
}

func TestCheckSourceContract(t *testing.T) {
	valid := BcryptTemplate()
	cases := []struct {
		name    string
		src     string
		wantErr string
	}{
		{name: "default", src: valid},
		{
			name: "alias",
			src:  "package hashalgo\n\nimport ph \"github.com/bravo68web/oauth-impl/pkg/passhash\"\n\nfunc Hash() ph.Hasher { return nil }\n",
		},
		{
			name: "method is not a second function",
			src:  valid + "\ntype box struct{}\nfunc (box) ID() string { return \"box\" }\n",
		},
		{
			name:    "second export",
			src:     valid + "\nfunc Extra() {}\n",
			wantErr: "exactly one function",
		},
		{
			name:    "renamed",
			src:     strings.Replace(valid, "func Hash()", "func PasswordHash()", 1),
			wantErr: "named Hash",
		},
		{
			name:    "wrong signature",
			src:     strings.Replace(valid, "func Hash()", "func Hash(password string)", 1),
			wantErr: "func() passhash.Hasher",
		},
		{
			name:    "wrong result",
			src:     "package hashalgo\n\nfunc Hash() string { return \"\" }\n",
			wantErr: "passhash.Hasher",
		},
		{
			name:    "wrong package",
			src:     strings.Replace(valid, "package hashalgo", "package main", 1),
			wantErr: "package must be hashalgo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSource(tc.name+".go", []byte(tc.src))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestArgon2TemplateChecks(t *testing.T) {
	if err := CheckSource("algo.go", []byte(Argon2Template)); err != nil {
		t.Fatal(err)
	}
}

func TestExamplesAreDropInHashers(t *testing.T) {
	entries, err := os.ReadDir("examples")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		n++
		path := filepath.Join("examples", entry.Name(), "algo.go")
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckSource(path, src); err != nil {
			t.Errorf("%s: %v", entry.Name(), err)
		}
		if entry.Name() == "argon2id" && !bytes.Equal(src, []byte(Argon2Template)) {
			t.Errorf("argon2id example drifted from init --hash argon2id")
		}
	}
	if n != 9 {
		t.Fatalf("example count = %d", n)
	}
}
