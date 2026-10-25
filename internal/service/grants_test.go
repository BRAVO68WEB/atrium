package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
)

func TestRevokeGrantRemovesConsentAndTokens(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "grants.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	consents := repository.NewConsentRepository(db)
	tokens := repository.NewTokenRepository(db)
	clients := repository.NewClientRepository(db)
	users := repository.NewUserRepository(db)
	now := time.Now().UTC()
	if err := users.Create(&models.User{ID: "user-1", Username: "ada", PasswordHash: "x", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, client := range []*models.Client{
		{ID: "app", Secret: "s", Name: "Field Notes", TokenEndpointAuthMethod: "client_secret_basic", CreatedAt: now, UpdatedAt: now},
		{ID: "other", Secret: "s", Name: "Other", TokenEndpointAuthMethod: "client_secret_basic", CreatedAt: now, UpdatedAt: now},
	} {
		if err := clients.Create(client); err != nil {
			t.Fatal(err)
		}
	}
	grants := NewGrantService(consents, tokens, clients)

	if err := consents.Save("user-1", "app", []string{"openid", "profile"}); err != nil {
		t.Fatal(err)
	}
	if err := consents.Save("user-1", "other", []string{"email"}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := tokens.SaveAccessToken(&models.AccessToken{Token: "access-app", ClientID: "app", UserID: "user-1", Scopes: []string{"openid"}, TokenType: "Bearer", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if err := tokens.SaveRefreshToken(&models.RefreshToken{Token: "refresh-app", ClientID: "app", UserID: "user-1", Scopes: []string{"openid"}, ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if err := tokens.SaveAccessToken(&models.AccessToken{Token: "access-other", ClientID: "other", UserID: "user-1", Scopes: []string{"email"}, TokenType: "Bearer", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}

	listed, err := grants.List("user-1")
	if err != nil || len(listed) != 2 {
		t.Fatalf("list %+v err=%v", listed, err)
	}
	var app *GrantedApp
	for i := range listed {
		if listed[i].ClientID == "app" {
			app = &listed[i]
		}
	}
	if app == nil || app.Name != "Field Notes" || app.Initial != "F" {
		t.Fatalf("app grant %+v", app)
	}
	if err := grants.Revoke("user-1", "app"); err != nil {
		t.Fatal(err)
	}
	if _, err := consents.Get("user-1", "app"); err == nil {
		t.Fatal("consent still present")
	}
	access, err := tokens.GetAccessToken("access-app")
	if err != nil || !access.Revoked {
		t.Fatalf("app access revoked=%v err=%v", access, err)
	}
	other, err := tokens.GetAccessToken("access-other")
	if err != nil || other.Revoked {
		t.Fatalf("other access revoked=%v err=%v", other, err)
	}
	refresh, err := tokens.GetRefreshToken("refresh-app")
	if err != nil || !refresh.Revoked {
		t.Fatalf("app refresh revoked=%v err=%v", refresh, err)
	}
	left, err := grants.List("user-1")
	if err != nil || len(left) != 1 || left[0].ClientID != "other" {
		t.Fatalf("remaining %+v err=%v", left, err)
	}
}
