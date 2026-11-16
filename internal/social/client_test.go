package social

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/atrium/internal/config"
)

func TestGitLabPreset(t *testing.T) {
	p, err := Resolve(config.SocialProvider{ID: "gl", Type: "gitlab"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer != "https://gitlab.com" || p.Authorization != "https://gitlab.com/oauth/authorize" || p.Token != "https://gitlab.com/oauth/token" || p.Userinfo != "https://gitlab.com/oauth/userinfo" {
		t.Fatalf("gitlab endpoints %+v", p)
	}
	if p.SubjectField != "sub" || p.UsernameField != "preferred_username" || len(p.Scopes) != 3 {
		t.Fatalf("gitlab profile %+v", p)
	}
}

func TestDiscoverIssuer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "http://127.0.0.1",
			"authorization_endpoint": "https://idp.example/authorize",
			"token_endpoint":         "https://idp.example/token",
			"userinfo_endpoint":      "https://idp.example/userinfo",
			"jwks_uri":               "https://idp.example/jwks",
		})
	}))
	defer srv.Close()
	doc, err := DiscoverIssuer(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if doc.AuthorizationEndpoint != "https://idp.example/authorize" || doc.TokenEndpoint != "https://idp.example/token" || doc.UserinfoEndpoint != "https://idp.example/userinfo" {
		t.Fatalf("%+v", doc)
	}
	if _, err := DiscoverIssuer(context.Background(), "http://idp.example"); err == nil {
		t.Fatal("expected a non-local http issuer to be rejected")
	}
}

func TestFacebookAuthorizeSkipsPKCE(t *testing.T) {
	p, err := Resolve(config.SocialProvider{ID: "facebook", Type: "facebook", ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := AuthorizeURL(p, "https://app.example/cb", "state", "nonce", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "code_challenge") {
		t.Fatalf("facebook url has pkce: %s", raw)
	}
	if !strings.Contains(raw, "client_id=cid") || !strings.Contains(raw, "state=state") {
		t.Fatalf("url = %s", raw)
	}
}

func TestIDTokenProfile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []any{rsaJWK(&key.PublicKey, "k1")}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	claims := jwt.MapClaims{
		"iss":            "https://issuer.example",
		"aud":            "cid",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"sub":            "subject-1",
		"nonce":          "nonce-1",
		"email":          "ada@example.com",
		"email_verified": true,
		"name":           "Ada Lovelace",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	p := Resolved{
		Type: "oidc", ClientID: "cid", Issuer: "https://issuer.example",
		UseIDToken: true, jwks: srv.URL, SubjectField: "sub", EmailField: "email",
		EmailVerifiedField: "email_verified",
	}
	profile, err := NewClient(srv.Client()).Profile(context.Background(), p, "", tokenResult{IDToken: raw}, "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Subject != "subject-1" || profile.Email != "ada@example.com" || !profile.EmailVerified {
		t.Fatalf("profile = %+v", profile)
	}
	if profile.GivenName != "Ada" || profile.FamilyName != "Lovelace" {
		t.Fatalf("name = %s %s", profile.GivenName, profile.FamilyName)
	}
	if _, err := NewClient(srv.Client()).Profile(context.Background(), p, "", tokenResult{IDToken: raw}, "other"); err == nil {
		t.Fatal("expected nonce mismatch")
	}
}

func rsaJWK(pub *rsa.PublicKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
