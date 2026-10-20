package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/oauth-impl/internal/cache"
	"github.com/bravo68web/oauth-impl/internal/config"
)

func TestIssueIDJAGChecksTrustScopeAndReplay(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Issuer: "http://idp.example"},
		XAA: config.XAAConfig{
			Enabled: true,
			Trusts: []config.XAATrust{{
				ClientID:         "field-notes",
				Audience:         "https://notes.example/",
				ResourceClientID: "notes-api",
				Scopes:           []string{"notes.read"},
			}},
		},
	}
	cfg.Normalize()
	xaa := NewXAA(cfg, nil, cache.NewMemory())
	now := time.Now()
	xaa.now = func() time.Time { return now }
	claims := jwt.MapClaims{
		"iss":   "http://idp.example",
		"sub":   "user-1",
		"aud":   "field-notes",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"email": "ada@fieldnotes.example",
	}
	verify := func(string) (jwt.MapClaims, error) { return claims, nil }

	if _, _, _, err := xaa.Issue(context.Background(), "field-notes", "id-token", "https://other.example", "notes.read", verify, testSign); err == nil || err.Error() != "invalid_target" {
		t.Fatalf("audience %v", err)
	}
	if _, _, _, err := xaa.Issue(context.Background(), "field-notes", "id-token", "https://notes.example", "admin", verify, testSign); err == nil || err.Error() != "invalid_scope" {
		t.Fatalf("scope %v", err)
	}
	compact, granted, expiresIn, err := xaa.Issue(context.Background(), "field-notes", "id-token", "https://notes.example", "notes.read", verify, testSign)
	if err != nil {
		t.Fatal(err)
	}
	if expiresIn != 300 || granted != "notes.read" || !strings.HasPrefix(compact, config.XAAIDJAGTyp+".") {
		t.Fatalf("issued %d %s %s", expiresIn, granted, compact)
	}
	issued := decodeSignedClaims(t, compact)
	if issued["client_id"] != "notes-api" || issued["aud"] != "https://notes.example" {
		t.Fatalf("claims %v", issued)
	}
	if issued["email"] != "ada@fieldnotes.example" || issued["scope"] != "notes.read" {
		t.Fatalf("identity %v", issued)
	}
	exp, _ := issued["exp"].(float64)
	iat, _ := issued["iat"].(float64)
	jti, _ := issued["jti"].(string)
	if int64(exp-iat) != 300 || issued["sub"] != "user-1" || jti == "" {
		t.Fatalf("time %v", issued)
	}
	if _, _, _, err := xaa.Issue(context.Background(), "field-notes", "id-token", "https://notes.example", "notes.read", verify, testSign); err == nil || err.Error() != "invalid_grant" {
		t.Fatalf("replay %v", err)
	}
}

func TestIssueDoesNotBurnTheIDTokenWhenSigningFails(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{Issuer: "http://idp.example"},
		XAA: config.XAAConfig{
			Enabled: true,
			Trusts: []config.XAATrust{{
				ClientID:         "field-notes",
				Audience:         "https://notes.example",
				ResourceClientID: "notes-api",
				Scopes:           []string{"notes.read"},
			}},
		},
	}
	cfg.Normalize()
	xaa := NewXAA(cfg, nil, cache.NewMemory())
	now := time.Now()
	xaa.now = func() time.Time { return now }
	claims := jwt.MapClaims{
		"iss": "http://idp.example",
		"sub": "user-1",
		"aud": "field-notes",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	verify := func(string) (jwt.MapClaims, error) { return claims, nil }
	attempts := 0
	sign := func(issued jwt.MapClaims, typ string) (string, error) {
		attempts++
		if attempts == 1 {
			return "", fmt.Errorf("no signing key")
		}
		return testSign(issued, typ)
	}
	if _, _, _, err := xaa.Issue(context.Background(), "field-notes", "id-token", "https://notes.example", "notes.read", verify, sign); err == nil || err.Error() != "server_error" {
		t.Fatalf("first %v", err)
	}
	compact, _, _, err := xaa.Issue(context.Background(), "field-notes", "id-token", "https://notes.example", "notes.read", verify, sign)
	if err != nil || compact == "" {
		t.Fatalf("second %v %s", err, compact)
	}
}

func TestIssueStaysOffWhenDisabled(t *testing.T) {
	xaa := NewXAA(config.DefaultConfig(), nil, cache.NewMemory())
	_, _, _, err := xaa.Issue(context.Background(), "field-notes", "id-token", "https://notes.example", "notes.read", nil, nil)
	if err == nil || err.Error() != "invalid_request" {
		t.Fatalf("err %v", err)
	}
}

func testSign(claims jwt.MapClaims, typ string) (string, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return typ + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeSignedClaims(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.SplitN(compact, ".", 2)
	if len(parts) != 2 {
		t.Fatalf("compact %s", compact)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
