package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
)

func TestTokensCarryTheOrgRole(t *testing.T) {
	db := testpg.Open(t)
	if err := repository.NewUserRepository(db).Create(&models.User{
		ID: "user-1", Username: "ada", PasswordHash: "x", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	orgs := repository.NewOrgRepository(db)
	if err := orgs.Create(&models.Organization{ID: "org-1", Slug: "acme-corp", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := orgs.AddMember("org-1", "user-1", "admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(db, config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	access, err := handler.CreateAccessTokenJWT(context.Background(), "app", "user-1", "openid", "Bearer", time.Hour, "org-1", "acme-corp", "", "")
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := handler.CreateIDToken(context.Background(), "app", "user-1", "", []string{"openid"}, IDTokenExtra{OrgID: "org-1", OrgSlug: "acme-corp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{access, idToken} {
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
			t.Fatal(err)
		}
		if claims["org_id"] != "org-1" || claims["org_slug"] != "acme-corp" || claims["org_role"] != "admin" {
			t.Fatalf("claims %#v", claims)
		}
	}
}
