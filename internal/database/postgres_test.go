package database_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
)

func pgID(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return "pg-" + hex.EncodeToString(buf)
}

func TestPostgresMigrateRoundTrip(t *testing.T) {
	db, dsn := testpg.OpenDSN(t)
	if err := db.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	_ = dsn

	id := pgID(t)
	users := repository.NewUserRepository(db)
	if err := users.Create(&models.User{
		ID: id, Username: "user-" + id, PasswordHash: "hash",
		Email: "user@example.com", EmailVerified: true, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := users.GetByUsername("user-" + id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id || !got.EmailVerified {
		t.Fatalf("user = %+v", got)
	}

	clients := repository.NewClientRepository(db)
	now := time.Now().UTC().Truncate(time.Second)
	if err := clients.Create(&models.Client{
		ID: id, Secret: "secret", Name: "Postgres App",
		RedirectURIs:            []string{"https://example.com/cb"},
		GrantTypes:              []string{"client_credentials"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		DCREnabled:              true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	client, err := clients.GetByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if client.Name != "Postgres App" || !client.DCREnabled || client.CreatedAt.IsZero() {
		t.Fatalf("client = %+v", client)
	}
}
