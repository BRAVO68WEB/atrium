package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/go-chi/chi/v5"
)

func TestClientJWKSRoute(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	repo := repository.NewClientRepository(db)
	if err := repo.Create(&models.Client{ID: "app", Name: "App", Secret: "secret"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(&models.Client{ID: "key", Name: "Management", Secret: "secret"}); err != nil {
		t.Fatal(err)
	}
	keys := service.NewClientKeyService(repo, "http://issuer.example", time.Hour)
	mgmt := NewManagementController(service.NewClientService(repo), nil, nil, nil, nil, nil, nil, nil, nil, nil)
	mgmt.SetClientKeys(keys)
	mgmt.SetManagementClientID("key")
	mux := chi.NewRouter()
	mux.Post("/api/clients/{clientID}/secret", mgmt.HandleResetClientSecret)
	mux.Post("/api/clients/{clientID}/keys", mgmt.HandleCreateClientKey)
	mux.Post("/api/clients/{clientID}/keys/rotate", mgmt.HandleRotateClientKey)

	denied := httptest.NewRequest(http.MethodPost, "/api/clients/key/keys", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, denied)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("management create %d %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/clients/app/keys", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.JWKSURI != "http://issuer.example/oidc/jwks" || strings.Contains(rec.Body.String(), `"private_pem":""`) {
		t.Fatalf("uri %s", created.JWKSURI)
	}

	before, err := repo.GetByID("app")
	if err != nil {
		t.Fatal(err)
	}
	secretReq := httptest.NewRequest(http.MethodPost, "/api/clients/app/secret", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, secretReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset %d %s", rec.Code, rec.Body.String())
	}
	var reset struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reset); err != nil {
		t.Fatal(err)
	}
	if reset.Secret == "" || reset.Secret == before.Secret {
		t.Fatal("secret was not replaced")
	}
	after, err := repo.GetByID("app")
	if err != nil {
		t.Fatal(err)
	}
	if after.Secret != reset.Secret {
		t.Fatal("stored secret does not match the reset secret")
	}
	deniedSecret := httptest.NewRequest(http.MethodPost, "/api/clients/key/secret", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, deniedSecret)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("management reset %d %s", rec.Code, rec.Body.String())
	}
}
