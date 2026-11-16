package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
)

func TestOpaqueTokenBecomesAJWT(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	mgmt := managementToken(t, ts.URL)
	owner := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":        "Field Notes",
		"grant_types": []string{"password", config.OpaqueToJWTGrant},
		"scopes":      []string{"openid", "email"},
	})
	other := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":        "Other App",
		"grant_types": []string{config.OpaqueToJWTGrant},
		"scopes":      []string{"openid"},
	})
	user := createAPIUser(t, ts.URL, mgmt, "ada-jwt", "ada-jwt@fieldnotes.example", true)
	issued := passwordGrant(t, ts.URL, owner, user)
	opaque, _ := issued["access_token"].(string)
	if strings.Count(opaque, ".") == 2 {
		t.Fatalf("expected an opaque token, got %s", opaque)
	}

	status, denied := postForm(t, ts.URL+"/oauth/token", other["id"].(string), other["secret"].(string), url.Values{
		"grant_type":    {config.OpaqueToJWTGrant},
		"subject_token": {opaque},
	})
	if status != http.StatusBadRequest || denied["error"] != "invalid_grant" {
		t.Fatalf("other client %d %v", status, denied)
	}

	status, reserved := postForm(t, ts.URL+"/oauth/token", owner["id"].(string), owner["secret"].(string), url.Values{
		"grant_type":    {config.OpaqueToJWTGrant},
		"subject_token": {opaque},
		"claims":        {`{"sub":"someone-else"}`},
	})
	if status != http.StatusBadRequest || reserved["error"] != "invalid_request" {
		t.Fatalf("reserved %d %v", status, reserved)
	}

	status, exchanged := postForm(t, ts.URL+"/oauth/token", owner["id"].(string), owner["secret"].(string), url.Values{
		"grant_type":    {config.OpaqueToJWTGrant},
		"subject_token": {opaque},
		"claims":        {`{"tenant":"acme","level":2}`},
	})
	jwt, _ := exchanged["access_token"].(string)
	if status != http.StatusOK || strings.Count(jwt, ".") != 2 {
		t.Fatalf("exchange %d %v", status, exchanged)
	}
	claims := jwtPayload(t, jwt)
	if claims["tenant"] != "acme" || claims["level"].(float64) != 2 || claims["scope"] != issued["scope"] {
		t.Fatalf("claims %v", claims)
	}
	if claims["sub"] == "" || claims["iss"] == "" {
		t.Fatalf("identity claims %v", claims)
	}

	info := introspectAs(t, ts.URL, owner, jwt)
	if info["active"] != true {
		t.Fatalf("introspect %v", info)
	}
	still := introspectAs(t, ts.URL, owner, opaque)
	if still["active"] != true {
		t.Fatalf("opaque token was revoked %v", still)
	}
}

func jwtPayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt %s", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
