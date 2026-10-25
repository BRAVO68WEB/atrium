package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

	"github.com/bravo68web/atrium/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

func TestJARAcceptsARS256ObjectAndRejectsNone(t *testing.T) {
	key := jarPrivateKey(t)
	other := jarPrivateKey(t)
	client := &models.Client{
		ID:   "app",
		JWKS: jwksJSON(t, jarPublicJWK(key, "app-key"), jarPublicJWK(other, "other-key")),
	}
	svc := NewJARService("https://issuer.example")
	raw := signRequest(t, jwt.SigningMethodRS256, key, "app-key", "http://127.0.0.1:9/jwks", jwt.MapClaims{
		"iss":            "app",
		"aud":            "https://issuer.example",
		"exp":            time.Now().Add(time.Minute).Unix(),
		"client_id":      "app",
		"redirect_uri":   "https://app.example/cb",
		"code_challenge": "challenge",
	})
	params, err := svc.ValidateRequestObject(raw, client)
	if err != nil {
		t.Fatal(err)
	}
	if params["client_id"] != "app" || params["redirect_uri"] != "https://app.example/cb" || params["code_challenge"] != "challenge" {
		t.Fatalf("params %v", params)
	}

	none := unsignedRequest(`{"alg":"none"}`, `{"client_id":"app"}`)
	if _, err := svc.ValidateRequestObject(none, client); err == nil || !strings.Contains(err.Error(), "must be signed") {
		t.Fatalf("none %v", err)
	}

	badKid := signRequest(t, jwt.SigningMethodRS256, key, "missing", "", jwt.MapClaims{
		"iss":       "app",
		"client_id": "app",
	})
	if _, err := svc.ValidateRequestObject(badKid, client); err == nil || !strings.Contains(err.Error(), "no matching key") {
		t.Fatalf("bad kid %v", err)
	}
}

func TestJARAcceptsOneECKeyWithoutAKID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &models.Client{ID: "app", JWKS: jwksJSON(t, ecJWK(t, &key.PublicKey))}
	raw := signRequest(t, jwt.SigningMethodES256, key, "", "", jwt.MapClaims{
		"client_id":    "app",
		"redirect_uri": "https://app.example/cb",
	})
	params, err := NewJARService("https://issuer.example").ValidateRequestObject(raw, client)
	if err != nil {
		t.Fatal(err)
	}
	if params["redirect_uri"] != "https://app.example/cb" {
		t.Fatalf("params %v", params)
	}
}

func TestJARRejectsALoopbackJWKSURI(t *testing.T) {
	key := jarPrivateKey(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(jwksJSON(t, jarPublicJWK(key, "remote"))))
	}))
	defer jwks.Close()
	client := &models.Client{ID: "app", JWKSUri: jwks.URL}
	raw := signRequest(t, jwt.SigningMethodRS256, key, "remote", "", jwt.MapClaims{"client_id": "app"})
	_, err := NewJARService("https://issuer.example").ValidateRequestObject(raw, client)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("jwks uri %v", err)
	}
}

func signRequest(t *testing.T, method jwt.SigningMethod, key any, kid, jku string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	if jku != "" {
		token.Header["jku"] = jku
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func unsignedRequest(header, payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "."
}

func jarPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jarPublicJWK(key *rsa.PrivateKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func ecJWK(t *testing.T, key *ecdsa.PublicKey) JWK {
	t.Helper()
	raw, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[0] != 4 || (len(raw)-1)%2 != 0 {
		t.Fatalf("public key bytes %x", raw)
	}
	size := (len(raw) - 1) / 2
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Alg: "ES256",
		X:   base64.RawURLEncoding.EncodeToString(raw[1 : 1+size]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[1+size:]),
	}
}

func jwksJSON(t *testing.T, keys ...JWK) string {
	t.Helper()
	raw, err := json.Marshal(JWKS{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
