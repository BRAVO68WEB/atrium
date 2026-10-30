package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
)

func TestMainJWKSIncludesApplicationKeys(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "jwks.db"))
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
	const publicJWK = `{"kty":"RSA","kid":"app-key","use":"sig","alg":"RS256","n":"abc","e":"AQAB"}`
	if err := repo.InsertClientSigningKey(repository.ClientSigningKey{
		ClientID: "app", Kid: "app-key", Alg: "RS256", PrivatePEM: "private", PublicJWK: publicJWK, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(db, config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.HandleJWKS(rec, httptest.NewRequest(http.MethodGet, "/oidc/jwks", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks %d %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, key := range doc.Keys {
		if key.Kid == "app-key" {
			found = true
		}
	}
	if !found || len(doc.Keys) < 3 || strings.Contains(rec.Body.String(), "private") {
		t.Fatalf("keys %+v body %s", doc.Keys, rec.Body.String())
	}
}
