package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/go-jose/go-jose/v4"
)

func TestIDTokenIsNestedJWEWhenClientAsks(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "jwe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "enc-1", Algorithm: encAlgRSAOAEP256, Use: "enc"}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	client := &models.Client{
		ID: "app", Secret: "s", Name: "app", TokenEndpointAuthMethod: "client_secret_basic",
		JWKS: string(raw), IDTokenEncryptedResponseAlg: encAlgRSAOAEP256, IDTokenEncryptedResponseEnc: encA256GCM,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := repository.NewClientRepository(db).Create(client); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(db, &config.Config{Security: config.SecurityConfig{Issuer: "http://issuer.example"}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := handler.CreateIDToken(context.Background(), "app", "user-1", "nonce", []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(token, ".") != 4 {
		t.Fatalf("compact JWE parts = %d, token %s", strings.Count(token, ".")+1, token)
	}
	object, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.RSA_OAEP_256}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := object.Decrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(plain), ".") != 2 {
		t.Fatalf("inner token = %s", plain)
	}
}
