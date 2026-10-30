package service

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/golang-jwt/jwt/v5"
)

func TestClientSigningKeyIsStoredAndPublished(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	repo := repository.NewClientRepository(db)
	repo.SetKey([]byte("0123456789abcdef0123456789abcdef"))
	if err := repo.Create(&models.Client{ID: "app", Name: "App", Secret: "secret"}); err != nil {
		t.Fatal(err)
	}
	svc := NewClientKeyService(repo, "http://issuer.example/", time.Hour)
	created, err := svc.Create("app")
	if err != nil {
		t.Fatal(err)
	}
	if created.Alg != "RS256" || created.JWKSURI != "http://issuer.example/oidc/jwks" || !strings.Contains(created.PrivatePEM, "RSA PRIVATE KEY") {
		t.Fatalf("created %+v", created)
	}
	var stored string
	if err := db.QueryRow(`SELECT private_pem FROM client_signing_keys WHERE kid = ?`, created.Kid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("private key stored as %q", stored[:12])
	}
	client, err := repo.GetByID("app")
	if err != nil {
		t.Fatal(err)
	}
	if client.JWKSUri != created.JWKSURI || !strings.Contains(client.JWKS, created.Kid) {
		t.Fatalf("published jwks %s uri %s", client.JWKS, client.JWKSUri)
	}
	block, _ := pem.Decode([]byte(created.PrivatePEM))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": "app", "sub": "app", "aud": "http://issuer.example", "exp": time.Now().Add(time.Hour).Unix(), "jti": "once"}
	raw := signRequest(t, jwt.SigningMethodRS256, key, created.Kid, "", claims)
	if err := VerifyClientAssertion(t.Context(), nil, NewJARService("http://issuer.example"), client, raw, clientAssertionType, "http://issuer.example", "http://issuer.example/oauth/token"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create("app"); err != ErrClientKeyExists {
		t.Fatalf("second create %v", err)
	}

	rotated, err := svc.Rotate("app")
	if err != nil {
		t.Fatal(err)
	}
	body, err := svc.PublicJWKS("app")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "PRIVATE") || !strings.Contains(string(body), created.Kid) || !strings.Contains(string(body), rotated.Kid) {
		t.Fatalf("jwks %s", body)
	}
	if _, err := db.Exec(`UPDATE client_signing_keys SET retire_at = ? WHERE kid = ?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), created.Kid); err != nil {
		t.Fatal(err)
	}
	body, err = svc.PublicJWKS("app")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0].Kid != rotated.Kid {
		t.Fatalf("after retain %+v", doc.Keys)
	}
	if _, err := svc.PublicJWKS("missing"); err != ErrClientNotFound {
		t.Fatalf("missing %v", err)
	}
}
