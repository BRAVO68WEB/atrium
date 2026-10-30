package service

import (
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/cache"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

func TestClientSecretJWTAndReplay(t *testing.T) {
	client := &models.Client{ID: "app", Secret: "correct horse battery"}
	store := cache.NewMemory()
	keys := NewJARService("https://issuer.example")
	claims := jwt.MapClaims{
		"iss": "app",
		"sub": "app",
		"aud": "https://issuer.example/oauth/token",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-5 * time.Second).Unix(),
		"jti": "once",
	}
	raw := signRequest(t, jwt.SigningMethodHS256, []byte(client.Secret), "", "", claims)
	if err := VerifyClientAssertion(t.Context(), store, keys, client, raw, clientAssertionType, "https://issuer.example", "https://issuer.example/oauth/par"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyClientAssertion(t.Context(), store, keys, client, raw, clientAssertionType, "https://issuer.example", "https://issuer.example/oauth/par"); err == nil {
		t.Fatal("replay was accepted")
	}
	claims["jti"] = "bad-sig"
	bad := signRequest(t, jwt.SigningMethodHS256, []byte("other-secret"), "", "", claims)
	if err := VerifyClientAssertion(t.Context(), store, keys, client, bad, clientAssertionType, "https://issuer.example", "https://issuer.example/oauth/par"); err == nil {
		t.Fatal("bad signature was accepted")
	}
}

func TestPrivateKeyJWT(t *testing.T) {
	key := jarPrivateKey(t)
	client := &models.Client{ID: "app", JWKS: jwksJSON(t, jarPublicJWK(key, "app-key"))}
	claims := jwt.MapClaims{
		"iss": "app",
		"sub": "app",
		"aud": "https://issuer.example",
		"exp": time.Now().Add(time.Hour).Unix(),
		"jti": "pk-1",
	}
	raw := signRequest(t, jwt.SigningMethodRS256, key, "app-key", "", claims)
	if err := VerifyClientAssertion(t.Context(), nil, NewJARService("https://issuer.example"), client, raw, clientAssertionType, "https://issuer.example", "https://issuer.example/oauth/token"); err != nil {
		t.Fatal(err)
	}
}
