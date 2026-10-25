package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
)

func TestIntrospectHidesOtherClients(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "intro.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	users := repository.NewUserRepository(db)
	tokens := repository.NewTokenRepository(db)
	clients := repository.NewClientRepository(db)
	now := time.Now().UTC()
	for _, id := range []string{"app", "other", "mgmt"} {
		if err := clients.Create(&models.Client{
			ID: id, Secret: "secret", Name: id, TokenEndpointAuthMethod: "client_secret_basic",
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := users.Create(&models.User{ID: "user-1", Username: "ada", PasswordHash: "x", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := tokens.SaveAccessToken(&models.AccessToken{
		Token: "access-1", ClientID: "app", UserID: "user-1", Scopes: []string{"openid", "profile"},
		TokenType: "Bearer", IssuedAt: issued, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := tokens.SaveRefreshToken(&models.RefreshToken{
		Token: "refresh-1", AccessToken: "access-1", ClientID: "app", UserID: "user-1",
		Scopes: []string{"openid"}, IssuedAt: issued, ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Security: config.SecurityConfig{Issuer: "http://issuer.example"}, Management: config.ManagementConfig{ClientID: "mgmt"}}
	svc := NewIntrospector(tokens, users, cfg)
	owner := &models.Client{ID: "app", TokenEndpointAuthMethod: "client_secret_basic"}
	other := &models.Client{ID: "other", TokenEndpointAuthMethod: "client_secret_basic"}
	mgmt := &models.Client{ID: "mgmt", TokenEndpointAuthMethod: "client_secret_basic"}
	public := &models.Client{ID: "app", TokenEndpointAuthMethod: "none"}

	got, err := svc.Introspect(owner, "access-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Active || got.Sub != "user-1" || got.Username != "ada" || got.Iss != "http://issuer.example" || got.Iat != issued.Unix() || got.Aud != "app" {
		t.Fatalf("%+v", got)
	}
	hidden, err := svc.Introspect(other, "access-1", "")
	if err != nil || hidden.Active {
		t.Fatalf("other client active=%v err=%v", hidden.Active, err)
	}
	seen, err := svc.Introspect(mgmt, "access-1", "")
	if err != nil || !seen.Active {
		t.Fatalf("management active=%v err=%v", seen.Active, err)
	}
	if _, err := svc.Introspect(public, "access-1", ""); err != ErrInvalidClient {
		t.Fatalf("public client err = %v", err)
	}
	refresh, err := svc.Introspect(owner, "refresh-1", "refresh_token")
	if err != nil || !refresh.Active || refresh.TokenType != "refresh_token" || refresh.Sub != "user-1" {
		t.Fatalf("%+v err=%v", refresh, err)
	}
	if err := tokens.RevokeAccessToken("access-1"); err != nil {
		t.Fatal(err)
	}
	revoked, err := svc.Introspect(owner, "access-1", "access_token")
	if err != nil || revoked.Active {
		t.Fatalf("revoked active=%v err=%v", revoked.Active, err)
	}
}
