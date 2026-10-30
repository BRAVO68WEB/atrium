package dashboard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
)

type fakeClients struct {
	client *models.Client
}

func (f fakeClients) ValidateClient(id, secret string) (*models.Client, error) {
	if f.client == nil || id != f.client.ID || secret != f.client.Secret {
		return nil, os.ErrNotExist
	}
	return f.client, nil
}

func TestDashboardLoginAndRedaction(t *testing.T) {
	api := chi.NewRouter()
	api.Get("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"c","name":"App","secret":"hide-me"}]`))
	})
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Branding.ProductName = "Atrium"
	dir := t.TempDir()
	cfg.File = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg.File, []byte("smtp:\n  host: mail.example\n  password: super-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := New(Options{
		Config: cfg,
		Clients: fakeClients{client: &models.Client{
			ID: "mgmt", Secret: "mgmt-secret", Name: "Management",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{service.ManagementScope},
			TokenEndpointAuthMethod: "client_secret_basic",
		}},
		Issue: func(id, secret string) (string, int, string) {
			if id == "mgmt" && secret == "mgmt-secret" {
				return "tok-1", http.StatusOK, ""
			}
			return "", http.StatusUnauthorized, "Invalid client credentials"
		},
		API: api,
	})
	r := chi.NewRouter()
	h.Mount(r)

	brand := call(t, r, http.MethodGet, "/dashboard/brand", "", "")
	if brand.Code != http.StatusOK || !strings.Contains(brand.Body.String(), `"product_name":"Atrium"`) || !strings.Contains(brand.Body.String(), `"primary_color":"#0066ff"`) {
		t.Fatalf("brand %d %s", brand.Code, brand.Body.String())
	}

	res := call(t, r, http.MethodPost, "/dashboard/session", `{"client_id":"mgmt","client_secret":"nope"}`, "")
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("bad secret status %d", res.Code)
	}

	res = call(t, r, http.MethodGet, "/dashboard/api/clients", "", "")
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status %d", res.Code)
	}

	res = call(t, r, http.MethodPost, "/dashboard/session", `{"client_id":"mgmt","client_secret":"mgmt-secret"}`, "")
	if res.Code != http.StatusOK {
		t.Fatalf("login %d %s", res.Code, res.Body.String())
	}
	var logged struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &logged); err != nil || logged.CSRF == "" {
		t.Fatal(res.Body.String())
	}
	if !strings.Contains(res.Header().Get("Set-Cookie"), "HttpOnly") {
		t.Fatalf("cookie %s", res.Header().Get("Set-Cookie"))
	}
	jar := cookieHeader(res)

	metaRes := call(t, r, http.MethodGet, "/dashboard/api/meta", "", jar)
	var metaBody struct {
		CSRF string `json:"csrf"`
	}
	if metaRes.Code != http.StatusOK || json.Unmarshal(metaRes.Body.Bytes(), &metaBody) != nil || metaBody.CSRF != logged.CSRF {
		t.Fatalf("meta csrf %d %s", metaRes.Code, metaRes.Body.String())
	}

	res = call(t, r, http.MethodGet, "/dashboard/api/clients", "", jar)
	if res.Code != http.StatusOK {
		t.Fatalf("list %d %s", res.Code, res.Body.String())
	}
	if strings.Contains(res.Body.String(), "hide-me") || !strings.Contains(res.Body.String(), "App") {
		t.Fatalf("body %s", res.Body.String())
	}

	res = call(t, r, http.MethodPut, "/dashboard/api/config", `{"smtp":{"host":"other.example","password":""}}`, jar)
	if res.Code != http.StatusForbidden {
		t.Fatalf("csrf status %d", res.Code)
	}
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/config", strings.NewReader(`{"smtp":{"host":"other.example","password":""}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", jar)
	req.Header.Set("X-CSRF-Token", logged.CSRF)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("save %d %s", rec.Code, rec.Body.String())
	}
	var saved struct {
		RestartRequired bool `json:"restart_required"`
		AutoRestart     bool `json:"auto_restart"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil || !saved.RestartRequired || saved.AutoRestart {
		t.Fatalf("saved %+v %s", saved, rec.Body.String())
	}
	file, err := os.ReadFile(cfg.File)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(file), "super-secret") || !strings.Contains(string(file), "other.example") {
		t.Fatalf("file\n%s", file)
	}

	mail := call(t, r, http.MethodGet, "/dashboard/api/themes/email", "", jar)
	if mail.Code != http.StatusOK || !strings.Contains(mail.Body.String(), `"name":"reset"`) || !strings.Contains(mail.Body.String(), "Password reset") {
		t.Fatalf("email themes %d %s", mail.Code, mail.Body.String())
	}

	page := call(t, r, http.MethodGet, "/dashboard", "", "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `id="root"`) {
		t.Fatalf("page %d location %q body %s", page.Code, page.Header().Get("Location"), page.Body.String())
	}
	nested := call(t, r, http.MethodGet, "/dashboard/applications", "", "")
	if nested.Code != http.StatusOK || !strings.Contains(nested.Body.String(), `id="root"`) {
		t.Fatalf("nested %d %s", nested.Code, nested.Body.String())
	}
}

func TestDashboardRejectsUserClient(t *testing.T) {
	h := New(Options{
		Config: config.DefaultConfig(),
		Clients: fakeClients{client: &models.Client{
			ID: "app", Secret: "secret",
			GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid"},
			TokenEndpointAuthMethod: "client_secret_basic",
		}},
		Issue: func(string, string) (string, int, string) { return "no", http.StatusOK, "" },
		API:   chi.NewRouter(),
	})
	r := chi.NewRouter()
	h.Mount(r)
	res := call(t, r, http.MethodPost, "/dashboard/session", `{"client_id":"app","client_secret":"secret"}`, "")
	if res.Code != http.StatusForbidden {
		t.Fatalf("status %d %s", res.Code, res.Body.String())
	}
}

func call(t *testing.T, h http.Handler, method, path, body, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func cookieHeader(res *httptest.ResponseRecorder) string {
	var parts []string
	for _, c := range res.Result().Cookies() {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}
