package database_test

import (
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func TestCredentialHashRunsOnce(t *testing.T) {
	db := testpg.Open(t)
	if _, err := db.Exec(`DELETE FROM schema_flags WHERE name = 'credential_hash_v1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO clients (id, secret, name) VALUES ('app', 'secret', 'App')`); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	if _, err := db.Exec(`INSERT INTO access_tokens (token, client_id, user_id, scopes, expires_at) VALUES ('access-token-1', 'app', 'user-1', '[]', ?)`, expires); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO refresh_tokens (token, access_token, client_id, user_id, scopes, expires_at) VALUES ('refresh-token-1', 'access-token-1', 'app', 'user-1', '[]', ?)`, expires); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	var access, refresh, link, id string
	if err := db.QueryRow(`SELECT token, COALESCE(id, '') FROM access_tokens`).Scan(&access, &id); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT token, access_token FROM refresh_tokens`).Scan(&refresh, &link); err != nil {
		t.Fatal(err)
	}
	want := crypto.CredentialHash("access-token-1")
	if access != want || link != want || refresh != crypto.CredentialHash("refresh-token-1") || id == "" {
		t.Fatalf("access=%s refresh=%s link=%s id=%s", access, refresh, link, id)
	}
}
