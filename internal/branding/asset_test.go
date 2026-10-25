package branding

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/config"
)

func TestAssetHandlerRejectsTraversalAndServesSVG(t *testing.T) {
	dir := t.TempDir()
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`
	if err := os.WriteFile(filepath.Join(dir, "mark.svg"), []byte(svg), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape.svg")); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Branding: config.BrandingConfig{AssetsDir: dir}}
	h := AssetHandler(cfg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, assetRequest("../config.yaml"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("traversal status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, assetRequest("escape.svg"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("symlink status = %d body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, assetRequest("mark.svg"))
	if rec.Code != http.StatusOK {
		t.Fatalf("svg status = %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("csp = %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("nosniff = %q", rec.Header().Get("X-Content-Type-Options"))
	}
	if !strings.Contains(rec.Body.String(), "<script>") {
		t.Fatal("svg body was rewritten")
	}
}

func TestAssetHandlerRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	body := make([]byte, config.MaxBrandAssetBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "big.png"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Branding: config.BrandingConfig{AssetsDir: dir}}
	rec := httptest.NewRecorder()
	AssetHandler(cfg).ServeHTTP(rec, assetRequest("big.png"))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
}

func assetRequest(name string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/branding/assets/"+name, nil)
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("name", name)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}
