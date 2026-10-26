package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/atrium/internal/config"
)

func TestUserMetadataMergeAndClaim(t *testing.T) {
	ts := setupConfigured(t, func(cfg *config.Config) {
		cfg.OIDC.ClaimMappings = []config.ClaimMapping{{
			Claim: "locale", Source: "user.locale", Scopes: []string{"profile"},
		}}
	})
	base := ts.URL
	mgmt := managementToken(t, base)
	created := apiObject(t, http.MethodPost, base+"/api/users", mgmt, map[string]any{
		"username":      "ada",
		"password":      "correct horse",
		"email":         "ada@example.com",
		"attributes":    map[string]string{"plan": "team", "region": "us"},
		"user_metadata": map[string]string{"locale": "en"},
	}, http.StatusCreated)
	userID, _ := created["id"].(string)
	if userID == "" {
		t.Fatalf("user %v", created)
	}
	if created["attributes"].(map[string]any)["plan"] != "team" || created["user_metadata"].(map[string]any)["locale"] != "en" {
		t.Fatalf("create %v", created)
	}

	named := apiObject(t, http.MethodPatch, base+"/api/users/"+userID, mgmt, map[string]any{
		"given_name": "Ada",
	}, http.StatusOK)
	attrs := named["attributes"].(map[string]any)
	if named["given_name"] != "Ada" || attrs["plan"] != "team" || attrs["region"] != "us" {
		t.Fatalf("untouched attributes %v", named)
	}

	merged := apiObject(t, http.MethodPatch, base+"/api/users/"+userID, mgmt, map[string]any{
		"attributes": map[string]any{"plan": nil, "seat": "1"},
	}, http.StatusOK)
	attrs = merged["attributes"].(map[string]any)
	if _, ok := attrs["plan"]; ok || attrs["region"] != "us" || attrs["seat"] != "1" {
		t.Fatalf("merged attributes %v", attrs)
	}

	client := createAPIClient(t, base, mgmt, map[string]any{
		"name":                       "Notes",
		"redirect_uris":              []string{"https://app.example/cb"},
		"grant_types":                []string{"password"},
		"scopes":                     []string{"openid", "profile", "email"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	status, grant := postForm(t, base+"/oauth/token", client["id"].(string), client["secret"].(string), url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"correct horse"},
		"scope":      {"openid profile"},
	})
	if status != http.StatusOK {
		t.Fatalf("grant %d %v", status, grant)
	}
	userToken := grant["access_token"].(string)
	assertClaim(t, grant["id_token"].(string), "locale", "en")

	me := apiObject(t, http.MethodGet, base+"/api/me", userToken, nil, http.StatusOK)
	if _, ok := me["attributes"]; ok {
		t.Fatalf("attributes on /api/me %v", me)
	}
	if me["user_metadata"].(map[string]any)["locale"] != "en" {
		t.Fatalf("me %v", me)
	}
	patched := apiObject(t, http.MethodPatch, base+"/api/me", userToken, map[string]any{
		"user_metadata": map[string]any{"locale": nil, "theme": "dark"},
	}, http.StatusOK)
	meta := patched["user_metadata"].(map[string]any)
	if _, ok := meta["locale"]; ok || meta["theme"] != "dark" {
		t.Fatalf("patched me %v", meta)
	}
	if _, ok := patched["attributes"]; ok {
		t.Fatalf("attributes on patched /api/me %v", patched)
	}

	for _, body := range []map[string]any{
		{"attributes": map[string]string{"plan": "team"}},
		{"disabled": true},
		{"email_verified": true},
	} {
		code, raw := apiCall(t, http.MethodPatch, base+"/api/me", userToken, body)
		if code != http.StatusBadRequest {
			t.Fatalf("status %d body %s", code, raw)
		}
	}
	me = apiObject(t, http.MethodGet, base+"/api/me", userToken, nil, http.StatusOK)
	if me["user_metadata"].(map[string]any)["theme"] != "dark" || me["disabled"] == true {
		t.Fatalf("me after reject %v", me)
	}

	status, grant = postForm(t, base+"/oauth/token", client["id"].(string), client["secret"].(string), url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"correct horse"},
		"scope":      {"openid profile"},
	})
	if status != http.StatusOK {
		t.Fatalf("second grant %d %v", status, grant)
	}
	claims := unverifiedClaims(t, grant["id_token"].(string))
	if _, ok := claims["locale"]; ok {
		t.Fatalf("locale remained %#v", claims)
	}

	backup := apiObject(t, http.MethodGet, base+"/api/backup", mgmt, nil, http.StatusOK)
	backed := backupUser(t, backup, "ada")
	backedAttrs := backed["attributes"].(map[string]any)
	backedMeta := backed["user_metadata"].(map[string]any)
	if backedAttrs["region"] != "us" || backedAttrs["seat"] != "1" || backedMeta["theme"] != "dark" {
		t.Fatalf("backup user %v", backed)
	}

	target := setupConfigured(t, nil)
	targetToken := managementToken(t, target.URL)
	raw, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, target.URL+"/api/restore", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+targetToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var restored map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&restored); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("restore %d %v", resp.StatusCode, restored)
	}
	again := apiObject(t, http.MethodGet, target.URL+"/api/users/"+userID, targetToken, nil, http.StatusOK)
	againAttrs := again["attributes"].(map[string]any)
	againMeta := again["user_metadata"].(map[string]any)
	if againAttrs["region"] != "us" || againAttrs["seat"] != "1" || againMeta["theme"] != "dark" {
		t.Fatalf("restored %v", again)
	}
}

func assertClaim(t *testing.T, token, key, want string) {
	t.Helper()
	claims := unverifiedClaims(t, token)
	if claims[key] != want {
		t.Fatalf("%s = %#v", key, claims[key])
	}
}

func unverifiedClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func backupUser(t *testing.T, backup map[string]any, username string) map[string]any {
	t.Helper()
	rows, _ := backup["users"].([]any)
	for _, row := range rows {
		item, _ := row.(map[string]any)
		if item["username"] == username {
			return item
		}
	}
	t.Fatalf("backup missing %s", username)
	return nil
}
