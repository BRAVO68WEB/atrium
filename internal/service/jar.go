package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type JARService struct {
	issuer string
}

func NewJARService(issuer string) *JARService {
	defer telemetry.Step("service.NewJARService")()
	return &JARService{issuer: issuer}
}

type RequestObjectClaims struct {
	jwt.RegisteredClaims
	ClientID            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	Prompt              string `json:"prompt,omitempty"`
	LoginHint           string `json:"login_hint,omitempty"`
	Resource            string `json:"resource,omitempty"`
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (s *JARService) ValidateRequestObject(requestJWT string, client *models.Client) (map[string]string, error) {
	defer
	// Parse JWT without verification first to get header
	telemetry.Step("service.JARService.ValidateRequestObject")()

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(requestJWT, &RequestObjectClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse request JWT: %w", err)
	}

	alg, _ := token.Header["alg"].(string)
	if !jarAlgOK(alg) {
		return nil, fmt.Errorf("request jwt must be signed")
	}
	if client == nil || (strings.TrimSpace(client.JWKS) == "" && strings.TrimSpace(client.JWKSUri) == "") {
		return nil, fmt.Errorf("client has no signing key")
	}
	pubKey, err := s.resolveClientKey(client, token.Header)
	if err != nil {
		return nil, fmt.Errorf("client signing key: %w", err)
	}
	token, err = jwt.ParseWithClaims(requestJWT, &RequestObjectClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != alg {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return pubKey, nil
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil {
		return nil, fmt.Errorf("invalid request JWT signature: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(*RequestObjectClaims)
	if !ok {
		return nil, fmt.Errorf("invalid request JWT claims")
	}

	// Validate iss == client_id (if present)
	if claims.Issuer != "" && claims.Issuer != client.ID {
		return nil, fmt.Errorf("iss mismatch: expected %s, got %s", client.ID, claims.Issuer)
	}

	// Validate aud (if present)
	if len(claims.Audience) > 0 {
		found := false
		for _, aud := range claims.Audience {
			if aud == s.issuer || aud == strings.TrimSuffix(s.issuer, "/") {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("aud mismatch: expected %s", s.issuer)
		}
	}

	// Validate exp (if present)
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("request JWT expired")
	}

	// Extract authorization parameters
	params := make(map[string]string)
	if claims.ClientID != "" {
		params["client_id"] = claims.ClientID
	}
	if claims.ResponseType != "" {
		params["response_type"] = claims.ResponseType
	}
	if claims.RedirectURI != "" {
		params["redirect_uri"] = claims.RedirectURI
	}
	if claims.Scope != "" {
		params["scope"] = claims.Scope
	}
	if claims.State != "" {
		params["state"] = claims.State
	}
	if claims.Nonce != "" {
		params["nonce"] = claims.Nonce
	}
	if claims.CodeChallenge != "" {
		params["code_challenge"] = claims.CodeChallenge
	}
	if claims.CodeChallengeMethod != "" {
		params["code_challenge_method"] = claims.CodeChallengeMethod
	}
	if claims.Prompt != "" {
		params["prompt"] = claims.Prompt
	}
	if claims.LoginHint != "" {
		params["login_hint"] = claims.LoginHint
	}
	if claims.Resource != "" {
		params["resource"] = claims.Resource
	}

	return params, nil
}

func jarAlgOK(alg string) bool {
	defer telemetry.Step("service.jarAlgOK")()
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

func (s *JARService) resolveClientKey(client *models.Client, header map[string]interface{}) (interface{}, error) {
	defer
	// Try inline JWKS first
	telemetry.Step("service.JARService.resolveClientKey")()

	if client.JWKS != "" {
		return s.getKeyFromJWKS(client.JWKS, header)
	}

	// Try JWKS URI
	if client.JWKSUri != "" {
		return s.getKeyFromJWKSUri(client.JWKSUri, header)
	}

	return nil, fmt.Errorf("no client key available (no jwks or jwks_uri configured)")
}

func (s *JARService) getKeyFromJWKS(jwksJSON string, header map[string]interface{}) (interface{}, error) {
	defer telemetry.Step("service.JARService.getKeyFromJWKS")()
	var jwks JWKS
	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse client JWKS: %w", err)
	}

	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)

	for _, key := range jwks.Keys {
		// Match by kid if present
		if kid != "" && key.Kid != kid {
			continue
		}

		// Parse key based on kty
		switch key.Kty {
		case "RSA":
			return parseRSAJWK(key)
		case "EC":
			return parseECJWK(key)
		default:
			return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
		}
	}
	if kid == "" && len(jwks.Keys) == 1 {
		switch jwks.Keys[0].Kty {
		case "RSA":
			return parseRSAJWK(jwks.Keys[0])
		case "EC":
			return parseECJWK(jwks.Keys[0])
		}
	}

	return nil, fmt.Errorf("no matching key found in JWKS (alg=%s, kid=%s)", alg, kid)
}

func (s *JARService) getKeyFromJWKSUri(jwksUri string, header map[string]interface{}) (interface{}, error) {
	defer telemetry.Step("service.JARService.getKeyFromJWKSUri")()
	body, status, err := FetchSafe(context.Background(), nil, http.MethodGet, jwksUri, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksUri, err)
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("jwks endpoint returned %d", status)
	}
	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)

	for _, key := range jwks.Keys {
		if kid != "" && key.Kid != kid {
			continue
		}

		switch key.Kty {
		case "RSA":
			return parseRSAJWK(key)
		case "EC":
			return parseECJWK(key)
		}
	}
	if kid == "" && len(jwks.Keys) == 1 {
		switch jwks.Keys[0].Kty {
		case "RSA":
			return parseRSAJWK(jwks.Keys[0])
		case "EC":
			return parseECJWK(jwks.Keys[0])
		}
	}

	return nil, fmt.Errorf("no matching key found in JWKS URI (alg=%s, kid=%s)", alg, kid)
}

func parseRSAJWK(key JWK) (*rsa.PublicKey, error) {
	defer telemetry.Step("service.parseRSAJWK")()
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

func parseECJWK(key JWK) (*ecdsa.PublicKey, error) {
	defer telemetry.Step("service.parseECJWK")()
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC y: %w", err)
	}

	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", key.Crv)
	}

	return ecPublicKey(curve, xBytes, yBytes)
}

func ecPublicKey(curve elliptic.Curve, x, y []byte) (*ecdsa.PublicKey, error) {
	defer telemetry.Step("service.ecPublicKey")()
	size := (curve.Params().BitSize + 7) / 8
	if len(x) == 0 || len(y) == 0 || len(x) > size || len(y) > size {
		return nil, fmt.Errorf("invalid EC coordinates")
	}
	raw := make([]byte, 1+2*size)
	raw[0] = 4
	copy(raw[1+size-len(x):1+size], x)
	copy(raw[1+2*size-len(y):], y)
	return ecdsa.ParseUncompressedPublicKey(curve, raw)
}
