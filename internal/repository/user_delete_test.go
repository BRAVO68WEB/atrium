package repository

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
)

func TestDeleteUserRemovesLoginRows(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	users := NewUserRepository(db)
	user := &models.User{ID: "user-1", Username: "ada", PasswordHash: "hash", Email: "ada@example.com", CreatedAt: time.Now()}
	if err := users.Create(user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO clients (id, secret, name, redirect_uris, grant_types, scopes, created_at, updated_at) VALUES ('app', 's', 'App', '[]', '[]', '[]', ?, ?)`, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, expires_at) VALUES ('code', 'app', 'user-1', 'https://app.example/cb', ?)`, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO consents (id, user_id, client_id, scopes) VALUES ('c', 'user-1', 'app', '["openid"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sessions (id, user_id, username, auth_time, mfa_verified, created_at, expires_at, revoked) VALUES ('sid', 'user-1', 'ada', ?, 1, ?, ?, 0)`, time.Now(), time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := users.Delete("user-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := users.GetByID("user-1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("user still present: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM authorization_codes WHERE user_id = 'user-1'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("codes %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM consents WHERE user_id = 'user-1'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("consents %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id = 'user-1'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("sessions %d %v", n, err)
	}
	if err := users.Delete("missing"); err == nil {
		t.Fatal("missing user deleted")
	}
}

func TestClientSkipConsentRoundTrip(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "clients.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	clients := NewClientRepository(db)
	now := time.Now()
	client := &models.Client{
		ID: "envsync-web", Secret: "secret", Name: "Web",
		RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"authorization_code"},
		Scopes: []string{"openid"}, SkipConsent: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := clients.Create(client); err != nil {
		t.Fatal(err)
	}
	got, err := clients.GetByID("envsync-web")
	if err != nil || !got.SkipConsent || got.Secret != "secret" {
		t.Fatalf("got %+v %v", got, err)
	}
	got.SkipConsent = false
	if err := clients.Update(got); err != nil {
		t.Fatal(err)
	}
	got, err = clients.GetByID("envsync-web")
	if err != nil || got.SkipConsent {
		t.Fatalf("update did not clear skip: %+v %v", got, err)
	}
}
