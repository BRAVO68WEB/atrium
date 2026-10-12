package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	root "github.com/bravo68web/oauth-impl"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/go-chi/chi/v5"
)

func TestPreviewStaysOff(t *testing.T) {
	ctrl := previewController(t, false)
	if ctrl.PreviewEnabled() {
		t.Fatal("preview enabled by default")
	}
	rr := httptest.NewRecorder()
	ctrl.HandlePreview(rr, httptest.NewRequest(http.MethodGet, "/preview", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status %d", rr.Code)
	}
}

func TestPreviewCatalog(t *testing.T) {
	ctrl := previewController(t, true)
	router := chi.NewRouter()
	router.Get("/preview", ctrl.HandlePreview)
	router.Get("/preview/{page}", ctrl.HandlePreview)

	index := previewGet(t, router, "/preview")
	if index.Code != http.StatusOK || !strings.Contains(index.Body.String(), "/preview/consent") || !strings.Contains(index.Body.String(), "actor") {
		t.Fatalf("index %d %s", index.Code, index.Body.String())
	}
	login := previewGet(t, router, "/preview/login?variant=client")
	if !strings.Contains(login.Body.String(), "Continue to Field Notes") || !strings.Contains(login.Body.String(), `name="password"`) {
		t.Fatalf("login %s", login.Body.String())
	}
	consent := previewGet(t, router, "/preview/consent?variant=actor")
	body := consent.Body.String()
	if !strings.Contains(body, "Field Notes") || !strings.Contains(body, "Sign you in") || !strings.Contains(body, "openid") || !strings.Contains(body, "Finance Agent") || !strings.Contains(body, "notes.read") {
		t.Fatalf("consent %s", body)
	}
	missing := previewGet(t, router, "/preview/nope")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing %d", missing.Code)
	}
	ctrl.cfg.Debug.UI = false
	hidden := previewGet(t, router, "/preview/login")
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("disabled %d", hidden.Code)
	}
}

func previewController(t *testing.T, ui bool) *WebController {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Debug.UI = ui
	ctrl, err := NewWebController(nil, nil, nil, cfg, root.TemplateFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ctrl
}

func previewGet(t *testing.T, router http.Handler, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, rawURL, nil))
	if rr.Code != http.StatusOK && !strings.Contains(rawURL, "nope") && !strings.Contains(rawURL, "disabled") {
		if rr.Code >= 500 {
			t.Fatalf("%s %d %s", rawURL, rr.Code, rr.Body.String())
		}
	}
	return rr
}
