package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func TestBackupRestoresADirectoryOntoAnEmptyServer(t *testing.T) {
	source, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementToken(t, source.URL)
	user := createAPIUser(t, source.URL, token, "ada", "ada@example.com", true)
	client := createAPIClient(t, source.URL, token, map[string]any{
		"name":          "App",
		"redirect_uris": []string{"https://app.example/cb"},
		"grant_types":   []string{"authorization_code", "password"},
		"scopes":        []string{"openid", "email"},
	})
	approveBrowserConsent(t, source.URL, "ada", "correct-horse", client["id"].(string), "https://app.example/cb", "openid")

	backup := authedJSON(t, http.MethodGet, source.URL+"/api/backup", token, nil)
	keys, _ := backup["signing_keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("backup omitted signing keys")
	}
	var wantKid string
	for _, item := range keys {
		row, _ := item.(map[string]any)
		if row["alg"] == "RS256" && row["status"] == "active" {
			wantKid, _ = row["kid"].(string)
		}
	}
	if wantKid == "" {
		t.Fatal("backup has no active RS256 key")
	}

	target := setupConfigured(t, nil)
	targetToken := managementToken(t, target.URL)
	dryBody, _ := json.Marshal(backup)
	dryReq, _ := http.NewRequest(http.MethodPost, target.URL+"/api/restore?dry_run=true", bytes.NewReader(dryBody))
	dryReq.Header.Set("Authorization", "Bearer "+targetToken)
	dryReq.Header.Set("Content-Type", "application/json")
	dryResp, err := http.DefaultClient.Do(dryReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dryResp.Body.Close() }()
	var dry map[string]any
	if err := json.NewDecoder(dryResp.Body).Decode(&dry); err != nil {
		t.Fatal(err)
	}
	if dryResp.StatusCode != http.StatusOK || dry["dry_run"] != true {
		t.Fatalf("dry run %d %v", dryResp.StatusCode, dry)
	}
	if users := apiList(t, http.MethodGet, target.URL+"/api/users", targetToken, nil); len(users) != 0 {
		t.Fatalf("dry run wrote users: %v", users)
	}

	raw, _ := json.Marshal(backup)
	restoreReq, _ := http.NewRequest(http.MethodPost, target.URL+"/api/restore", bytes.NewReader(raw))
	restoreReq.Header.Set("Authorization", "Bearer "+targetToken)
	restoreReq.Header.Set("Content-Type", "application/json")
	restoreResp, err := http.DefaultClient.Do(restoreReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restoreResp.Body.Close() }()
	var restored map[string]any
	if err := json.NewDecoder(restoreResp.Body).Decode(&restored); err != nil {
		t.Fatal(err)
	}
	if restoreResp.StatusCode != http.StatusOK || restored["users"] == float64(0) {
		t.Fatalf("restore %d %v", restoreResp.StatusCode, restored)
	}
	passwordGrant(t, target.URL, client, user)

	jwksResp, err := http.Get(target.URL + "/oidc/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jwksResp.Body.Close() }()
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, key := range jwks.Keys {
		if key.Kid == wantKid {
			found = true
		}
	}
	if !found {
		t.Fatalf("jwks %+v missing %s", jwks.Keys, wantKid)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct-horse")
	login.Set("csrf_token", csrfToken(t, browser, target.URL+"/login"))
	loginResp, err := browser.PostForm(target.URL+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", client["id"].(string))
	query.Set("redirect_uri", "https://app.example/cb")
	query.Set("scope", "openid")
	query.Set("state", "again")
	authResp, err := browser.Get(target.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = authResp.Body.Close()
	loc := authResp.Header.Get("Location")
	if authResp.StatusCode != http.StatusFound || strings.Contains(loc, "/consent") || !strings.Contains(loc, "code=") {
		t.Fatalf("authorize after restore %d %s", authResp.StatusCode, loc)
	}

	again, _ := http.NewRequest(http.MethodPost, target.URL+"/api/restore", bytes.NewReader(raw))
	again.Header.Set("Authorization", "Bearer "+targetToken)
	again.Header.Set("Content-Type", "application/json")
	againResp, err := http.DefaultClient.Do(again)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = againResp.Body.Close() }()
	if againResp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(againResp.Body)
		t.Fatalf("second restore %d %s", againResp.StatusCode, body)
	}
}

func authedJSON(t *testing.T, method, rawURL, token string, payload []byte) map[string]any {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s %d %v", method, rawURL, resp.StatusCode, doc)
	}
	return doc
}
