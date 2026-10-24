package service

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

func TestBackupRestoresUsersClientsConsentsAndKeys(t *testing.T) {
	src := newBackupDB(t)
	users := repository.NewUserRepository(src.db)
	if err := users.Create(&models.User{
		ID: "user-ada", Username: "ada", PasswordHash: "stored-hash",
		Email: "ada@example.com", EmailVerified: true, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	clients := repository.NewClientRepository(src.db)
	if err := clients.Create(&models.Client{
		ID: "app", Secret: "app-secret", Name: "App",
		RedirectURIs: []string{"https://app.example/cb"},
		GrantTypes:   []string{"authorization_code", "password"},
		Scopes:       []string{"openid"},
		CreatedAt:    time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.NewConsentRepository(src.db).Save("user-ada", "app", []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	doc, err := src.backup.Export()
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Users) != 1 || doc.Users[0].PasswordHash != "stored-hash" || doc.Users[0].ID != "user-ada" {
		t.Fatalf("users %+v", doc.Users)
	}
	if len(doc.SigningKeys) < 2 {
		t.Fatalf("keys %d", len(doc.SigningKeys))
	}
	var wantKid string
	for _, key := range doc.SigningKeys {
		if key.Alg == "RS256" && key.Status == "active" {
			wantKid = key.Kid
		}
	}
	if wantKid == "" {
		t.Fatal("missing active RS256 key")
	}

	dst := newBackupDB(t)
	dry, err := dst.backup.Restore(doc, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || dry.Users != 1 {
		t.Fatalf("dry %+v", dry)
	}
	if _, err := repository.NewUserRepository(dst.db).GetByUsername("ada"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("dry run wrote the user: %v", err)
	}
	restored, err := dst.backup.Restore(doc, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Users != 1 || restored.Clients < 1 || restored.Consents != 1 || restored.SigningKeys < 2 {
		t.Fatalf("restore %+v", restored)
	}
	got, err := repository.NewUserRepository(dst.db).GetByUsername("ada")
	if err != nil || got.ID != "user-ada" || got.PasswordHash != "stored-hash" {
		t.Fatalf("user %+v %v", got, err)
	}
	consent, err := repository.NewConsentRepository(dst.db).Get("user-ada", "app")
	if err != nil || len(consent.Scopes) != 1 {
		t.Fatalf("consent %+v %v", consent, err)
	}
	found := false
	for _, key := range dst.keys.ToJWKS().Keys {
		if key.Kid == wantKid {
			found = true
		}
	}
	if !found {
		t.Fatalf("jwks missing %s in %+v", wantKid, dst.keys.ToJWKS().Keys)
	}
	if _, err := dst.backup.Restore(doc, false, false); !errors.Is(err, ErrRestoreConflict) {
		t.Fatalf("second restore %v", err)
	}
}

type backupFixture struct {
	db     *database.DB
	backup *Backup
	keys   *oidc.KeySet
}

func newBackupDB(t *testing.T) backupFixture {
	t.Helper()
	db, err := database.New(t.TempDir() + "/backup.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	keys, err := oidc.LoadKeySet(db)
	if err != nil {
		t.Fatal(err)
	}
	users := repository.NewUserRepository(db)
	clients := repository.NewClientRepository(db)
	orgs := repository.NewOrgRepository(db)
	scopes := repository.NewScopeRepository(db)
	resources := repository.NewResourceRepository(db)
	hooks := repository.NewWebhookRepository(db)
	return backupFixture{
		db: db, keys: keys,
		backup: NewBackup(db, users, clients, orgs, scopes, resources, hooks, "mgmt", keys),
	}
}
