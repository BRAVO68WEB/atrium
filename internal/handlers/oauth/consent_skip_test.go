package oauth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
)

func TestSkipConsentCountsAsConsented(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "consent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	clients := repository.NewClientRepository(db)
	now := time.Now()
	if err := clients.Create(&models.Client{
		ID: "envsync-web", Secret: "s", Name: "Web",
		RedirectURIs: []string{}, GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid"},
		SkipConsent: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{clientRepo: clients}
	if !h.hasConsented("user-1", "envsync-web", "openid") {
		t.Fatal("skip_consent did not count as consent")
	}
	if h.hasConsented("user-1", "missing", "openid") {
		t.Fatal("missing client counted as consented")
	}
}
