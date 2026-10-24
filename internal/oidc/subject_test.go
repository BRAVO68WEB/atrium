package oidc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/golang-jwt/jwt/v5"
)

func TestPairwiseSubDependsOnSector(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "pair.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	clients := repository.NewClientRepository(db)
	now := time.Now().UTC()
	sameA := &models.Client{ID: "a", Secret: "s", Name: "a", TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{"http://localhost/cb"}, SubjectType: "pairwise", CreatedAt: now, UpdatedAt: now}
	sameB := &models.Client{ID: "b", Secret: "s", Name: "b", TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{"http://localhost/other"}, SubjectType: "pairwise", CreatedAt: now, UpdatedAt: now}
	other := &models.Client{ID: "c", Secret: "s", Name: "c", TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{"http://127.0.0.1/cb"}, SubjectType: "pairwise", CreatedAt: now, UpdatedAt: now}
	public := &models.Client{ID: "d", Secret: "s", Name: "d", TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{"http://localhost/cb"}, SubjectType: "public", CreatedAt: now, UpdatedAt: now}
	for _, client := range []*models.Client{sameA, sameB, other, public} {
		if err := clients.Create(client); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := NewHandler(db, &config.Config{Security: config.SecurityConfig{Issuer: "http://issuer.example"}, OIDC: config.OIDCConfig{PairwiseSalt: "salt-1"}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := handler.CreateIDToken(context.Background(), "a", "user-1", "", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := handler.CreateIDToken(context.Background(), "b", "user-1", "", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	third, err := handler.CreateIDToken(context.Background(), "c", "user-1", "", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := handler.CreateIDToken(context.Background(), "d", "user-1", "", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	subA := claimSub(t, first)
	subB := claimSub(t, second)
	subC := claimSub(t, third)
	if subA != subB {
		t.Fatalf("same sector subs differ: %s %s", subA, subB)
	}
	if subA == subC {
		t.Fatal("different sectors produced the same sub")
	}
	if claimSub(t, plain) != "user-1" {
		t.Fatalf("public sub = %s", claimSub(t, plain))
	}
	if _, err := SectorHost([]string{"https://app.example/cb", "https://other.example/cb"}); err == nil {
		t.Fatal("expected mixed hosts to fail")
	}
}

func claimSub(t *testing.T, raw string) string {
	t.Helper()
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	return token.Claims.(jwt.MapClaims)["sub"].(string)
}
