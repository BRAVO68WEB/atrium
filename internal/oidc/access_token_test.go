package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/golang-jwt/jwt/v5"
)

func TestAccessTokenUsesJWTProfile(t *testing.T) {
	db := testpg.Open(t)
	handler, err := NewHandler(db, config.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handler.CreateAccessTokenJWT(context.Background(), "app", "user-1", "openid", "Bearer", time.Hour, "", "", "https://api.example", "actor-1")
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, claims)
	if err != nil {
		t.Fatal(err)
	}
	if token.Header["typ"] != "at+jwt" {
		t.Fatalf("typ %v", token.Header["typ"])
	}
	if claims["aud"] != "https://api.example" {
		t.Fatalf("aud %v", claims["aud"])
	}
	if claims["client_id"] != "app" || claims["azp"] != "app" || claims["sub"] != "user-1" {
		t.Fatalf("claims %v", claims)
	}
	act, _ := claims["act"].(map[string]any)
	if act["sub"] != "actor-1" {
		t.Fatalf("act %v", claims["act"])
	}
	issuerOnly, err := handler.CreateAccessTokenJWT(context.Background(), "app", "", "openid", "Bearer", time.Hour, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	empty := jwt.MapClaims{}
	if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(issuerOnly, empty); err != nil {
		t.Fatal(err)
	}
	if empty["aud"] != config.DefaultConfig().Security.Issuer || empty["sub"] != "app" {
		t.Fatalf("client token %v", empty)
	}
	if _, ok := empty["act"]; ok {
		t.Fatalf("act should be absent: %v", empty["act"])
	}
}
