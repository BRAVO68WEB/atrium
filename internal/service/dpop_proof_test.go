package service

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestDPoPRejectsAMissingTypeAndAStaleProof(t *testing.T) {
	svc := NewDPoPService()
	svc.SetMaxAge(time.Minute)
	key, err := svc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := svc.CreateDPoPProof(key, http.MethodPost, "https://issuer.example/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateDPoPProof(t.Context(), proof, http.MethodPost, "https://issuer.example/oauth/token", ""); err != nil {
		t.Fatal(err)
	}

	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	claims["iat"] = time.Now().Add(-2 * time.Minute).Unix()
	stale := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	stale.Header["typ"] = "dpop+jwt"
	stale.Header["jwk"] = token.Header["jwk"]
	raw, err := stale.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateDPoPProof(t.Context(), raw, http.MethodPost, "https://issuer.example/oauth/token", ""); err == nil {
		t.Fatal("stale proof accepted")
	}

	untyped := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": http.MethodPost,
		"htu": "https://issuer.example/oauth/token",
		"iat": time.Now().Unix(),
		"jti": "fresh",
	})
	untyped.Header["jwk"] = token.Header["jwk"]
	raw, err = untyped.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateDPoPProof(t.Context(), raw, http.MethodPost, "https://issuer.example/oauth/token", ""); err == nil {
		t.Fatal("proof without typ accepted")
	}
}
