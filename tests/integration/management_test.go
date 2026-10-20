package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestManagementAPI(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	base := ts.URL

	userStatus, userRaw := apiCall(t, http.MethodPost, base+"/api/users", token, map[string]any{
		"username": "ada",
		"password": "correct horse",
		"email":    "ada@example.com",
	})
	user := decodeObject(t, userStatus, userRaw, http.StatusCreated)
	userID, _ := user["id"].(string)
	if userID == "" || user["username"] != "ada" || user["email_verified"] != true {
		t.Fatalf("user %v", user)
	}

	listedUsers := apiList(t, http.MethodGet, base+"/api/users", token, nil)
	if !listHas(listedUsers, "id", userID) {
		t.Fatalf("users %v", listedUsers)
	}
	gotUser := apiObject(t, http.MethodGet, base+"/api/users/"+userID, token, nil)
	if gotUser["email"] != "ada@example.com" {
		t.Fatalf("get user %v", gotUser)
	}

	passStatus, passRaw := apiCall(t, http.MethodPost, base+"/api/users/"+userID+"/password", token, map[string]any{
		"password": "brand new horse",
	})
	if decodeObject(t, passStatus, passRaw, http.StatusOK)["status"] != "ok" {
		t.Fatalf("set password %s", passRaw)
	}

	app := apiObject(t, http.MethodPost, base+"/api/clients", token, map[string]any{
		"name":                                  "Notes",
		"redirect_uris":                         []string{"https://app.example/cb"},
		"grant_types":                           []string{"authorization_code", "password", "refresh_token"},
		"scopes":                                []string{"openid", "profile", "email"},
		"token_endpoint_auth_method":            "client_secret_basic",
		"dpop_bound_access_tokens":              false,
		"require_pushed_authorization_requests": false,
	})
	clientID, _ := app["id"].(string)
	clientSecret, _ := app["secret"].(string)
	if clientID == "" || clientSecret == "" || app["name"] != "Notes" {
		t.Fatalf("client %v", app)
	}
	if !listHas(apiList(t, http.MethodGet, base+"/api/clients", token, nil), "id", clientID) {
		t.Fatal("client missing from list")
	}
	if apiObject(t, http.MethodGet, base+"/api/clients/"+clientID, token, nil)["secret"] != clientSecret {
		t.Fatal("get client lost the secret")
	}

	updated := apiObject(t, http.MethodPut, base+"/api/clients/"+clientID, token, map[string]any{
		"name":                                  "Field Notes",
		"dpop_bound_access_tokens":              true,
		"require_pushed_authorization_requests": true,
	})
	if updated["name"] != "Field Notes" || updated["dpop_bound_access_tokens"] != true || updated["require_pushed_authorization_requests"] != true {
		t.Fatalf("update %v", updated)
	}

	spare := apiObject(t, http.MethodPost, base+"/api/clients", token, map[string]any{
		"name":          "Spare",
		"redirect_uris": []string{"https://spare.example/cb"},
		"grant_types":   []string{"client_credentials"},
	})
	spareID, _ := spare["id"].(string)
	if apiObject(t, http.MethodDelete, base+"/api/clients/"+spareID, token, nil)["status"] != "deleted" {
		t.Fatal("delete client")
	}
	missingStatus, missingRaw := apiCall(t, http.MethodGet, base+"/api/clients/"+spareID, token, nil)
	if decodeObject(t, missingStatus, missingRaw, http.StatusNotFound)["error"] != "not_found" {
		t.Fatalf("deleted client %d %s", missingStatus, missingRaw)
	}

	// DPoP was turned on, so the password grant needs it off again before it can mint a token.
	apiObject(t, http.MethodPut, base+"/api/clients/"+clientID, token, map[string]any{
		"dpop_bound_access_tokens":              false,
		"require_pushed_authorization_requests": true,
	})
	granted, grantBody := postForm(t, base+"/oauth/token", clientID, clientSecret, url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"brand new horse"},
		"scope":      {"openid profile"},
	})
	if granted != http.StatusOK {
		t.Fatalf("password grant %d %v", granted, grantBody)
	}
	accessToken, _ := grantBody["access_token"].(string)
	if accessToken == "" || grantBody["refresh_token"] == "" {
		t.Fatalf("grant %v", grantBody)
	}

	accessRows := apiList(t, http.MethodGet, base+"/api/tokens?user_id="+url.QueryEscape(userID), token, nil)
	if !listHas(accessRows, "token", accessToken) {
		t.Fatalf("tokens %v", accessRows)
	}
	revokedAccess := apiObject(t, http.MethodPost, base+"/api/tokens/"+url.PathEscape(accessToken)+"/revoke", token, nil)
	if revokedAccess["status"] != "revoked" {
		t.Fatalf("revoke access %v", revokedAccess)
	}
	if !listHasField(apiList(t, http.MethodGet, base+"/api/tokens?user_id="+url.QueryEscape(userID), token, nil), "token", accessToken, "revoked", true) {
		t.Fatal("access token still active")
	}

	refreshRows := apiList(t, http.MethodGet, base+"/api/refresh-tokens?user_id="+url.QueryEscape(userID), token, nil)
	refreshID := firstString(refreshRows, "id")
	if refreshID == "" || listHas(refreshRows, "token", grantBody["refresh_token"].(string)) {
		t.Fatalf("refresh list leaked or was empty %v", refreshRows)
	}
	if apiObject(t, http.MethodPost, base+"/api/refresh-tokens/"+refreshID+"/revoke", token, nil)["status"] != "revoked" {
		t.Fatal("revoke refresh")
	}

	oldGrant, _ := postForm(t, base+"/oauth/token", clientID, clientSecret, url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"correct horse"},
	})
	if oldGrant == http.StatusOK {
		t.Fatal("old password still works")
	}

	disabled := apiObject(t, http.MethodPatch, base+"/api/users/"+userID, token, map[string]any{"disabled": true})
	if disabled["disabled"] != true {
		t.Fatalf("disable %v", disabled)
	}
	blocked, _ := postForm(t, base+"/oauth/token", clientID, clientSecret, url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"brand new horse"},
	})
	if blocked == http.StatusOK {
		t.Fatal("disabled user received a token")
	}
	enabled := apiObject(t, http.MethodPatch, base+"/api/users/"+userID, token, map[string]any{"disabled": false})
	if enabled["disabled"] != false {
		t.Fatalf("enable %v", enabled)
	}

	approveBrowserConsent(t, base, "ada", "brand new horse", clientID, "https://app.example/cb", "openid profile")
	consents := apiList(t, http.MethodGet, base+"/api/consents?user_id="+url.QueryEscape(userID), token, nil)
	if !listHas(consents, "client_id", clientID) {
		t.Fatalf("consents %v", consents)
	}
	if apiObject(t, http.MethodDelete, base+"/api/consents?user_id="+url.QueryEscape(userID)+"&client_id="+url.QueryEscape(clientID), token, nil)["status"] != "revoked" {
		t.Fatal("revoke consent")
	}
	if listHas(apiList(t, http.MethodGet, base+"/api/consents?user_id="+url.QueryEscape(userID), token, nil), "client_id", clientID) {
		t.Fatal("consent remained")
	}

	sessions := apiList(t, http.MethodGet, base+"/api/users/"+userID+"/sessions", token, nil)
	sessionID := firstString(sessions, "id")
	if sessionID == "" {
		t.Fatalf("sessions %v", sessions)
	}
	if apiObject(t, http.MethodDelete, base+"/api/users/"+userID+"/sessions/"+sessionID, token, nil)["status"] != "revoked" {
		t.Fatal("revoke session")
	}
	if !listHasField(apiList(t, http.MethodGet, base+"/api/users/"+userID+"/sessions", token, nil), "id", sessionID, "revoked", true) {
		t.Fatal("session still active")
	}

	global := apiObject(t, http.MethodGet, base+"/api/analytics/logins?window=24h", token, nil)
	if global["successes"].(float64) < 1 {
		t.Fatalf("global analytics %v", global)
	}
	personal := apiObject(t, http.MethodGet, base+"/api/users/"+userID+"/login-analytics?window=24h", token, nil)
	if personal["successes"].(float64) < 1 {
		t.Fatalf("user analytics %v", personal)
	}
	activity := apiList(t, http.MethodGet, base+"/api/users/"+userID+"/activity", token, nil)
	if !listHas(activity, "success", true) {
		t.Fatalf("activity %v", activity)
	}

	mfaUser := apiObject(t, http.MethodPost, base+"/api/users", token, map[string]any{
		"username": "otto",
		"password": "correct horse",
		"email":    "otto@example.com",
	})
	mfaID, _ := mfaUser["id"].(string)
	enroll := apiObject(t, http.MethodPost, base+"/api/users/"+mfaID+"/mfa/enable", token, map[string]any{})
	secret, _ := enroll["secret"].(string)
	if secret == "" || enroll["qr_uri"] == "" || enroll["qr_base64"] == "" {
		t.Fatalf("enroll %v", enroll)
	}
	if apiObject(t, http.MethodGet, base+"/api/users/"+mfaID+"/mfa/status", token, nil)["mfa_enabled"] != false {
		t.Fatal("mfa enabled before confirm")
	}
	wrongCode := "000000"
	goodCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if goodCode == wrongCode {
		wrongCode = "111111"
	}
	wrongStatus, wrongRaw := apiCall(t, http.MethodPost, base+"/api/users/"+mfaID+"/mfa/verify", token, map[string]any{"code": wrongCode})
	if decodeObject(t, wrongStatus, wrongRaw, http.StatusBadRequest)["error"] != "invalid_grant" {
		t.Fatalf("wrong code %d %s", wrongStatus, wrongRaw)
	}
	if apiObject(t, http.MethodPost, base+"/api/users/"+mfaID+"/mfa/verify", token, map[string]any{"code": goodCode})["status"] != "mfa_enabled" {
		t.Fatal("confirm mfa")
	}
	if apiObject(t, http.MethodGet, base+"/api/users/"+mfaID+"/mfa/status", token, nil)["mfa_enabled"] != true {
		t.Fatal("mfa status")
	}
	if apiObject(t, http.MethodPost, base+"/api/users/"+mfaID+"/mfa/disable", token, map[string]any{})["status"] != "mfa_disabled" {
		t.Fatal("disable mfa")
	}

	scope := apiObject(t, http.MethodPost, base+"/api/scopes", token, map[string]any{
		"name":            "notes.read",
		"description":     "Read notes",
		"resource_server": "notes-api",
	})
	if scope["name"] != "notes.read" {
		t.Fatalf("scope %v", scope)
	}
	dupStatus, dupRaw := apiCall(t, http.MethodPost, base+"/api/scopes", token, map[string]any{"name": "notes.read"})
	if decodeObject(t, dupStatus, dupRaw, http.StatusConflict)["error"] != "already_exists" {
		t.Fatalf("duplicate scope %d %s", dupStatus, dupRaw)
	}
	if !listHas(apiList(t, http.MethodGet, base+"/api/scopes", token, nil), "name", "notes.read") {
		t.Fatal("scope list")
	}
	if apiObject(t, http.MethodGet, base+"/api/scopes/notes.read", token, nil)["description"] != "Read notes" {
		t.Fatal("get scope")
	}

	resource := apiObject(t, http.MethodPost, base+"/api/resources", token, map[string]any{
		"uri":         "notes-api",
		"name":        "Notes API",
		"description": "Notes",
		"scopes":      []string{"notes.read"},
	})
	if resource["uri"] != "notes-api" {
		t.Fatalf("resource %v", resource)
	}
	if !listHas(apiList(t, http.MethodGet, base+"/api/resources", token, nil), "uri", "notes-api") {
		t.Fatal("resource list")
	}
	if apiObject(t, http.MethodGet, base+"/api/resources/notes-api", token, nil)["name"] != "Notes API" {
		t.Fatal("get resource")
	}
	renamed := apiObject(t, http.MethodPut, base+"/api/resources/notes-api", token, map[string]any{
		"name":   "Field Notes API",
		"scopes": []string{"notes.read"},
	})
	if renamed["name"] != "Field Notes API" {
		t.Fatalf("update resource %v", renamed)
	}
	if !listHas(apiList(t, http.MethodGet, base+"/api/resources/notes-api/scopes", token, nil), "name", "notes.read") {
		t.Fatal("resource scopes")
	}
	if apiObject(t, http.MethodDelete, base+"/api/scopes/notes.read", token, nil)["status"] != "deleted" {
		t.Fatal("delete scope")
	}
	goneScope, goneScopeRaw := apiCall(t, http.MethodGet, base+"/api/scopes/notes.read", token, nil)
	if decodeObject(t, goneScope, goneScopeRaw, http.StatusNotFound)["error"] != "not_found" {
		t.Fatalf("scope remained %d %s", goneScope, goneScopeRaw)
	}
	if apiObject(t, http.MethodDelete, base+"/api/resources/notes-api", token, nil)["status"] != "deleted" {
		t.Fatal("delete resource")
	}

	var hits []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Header.Get("X-Webhook-Event"))
		if !strings.HasPrefix(r.Header.Get("X-Webhook-Signature"), "sha256=") {
			t.Errorf("signature %q", r.Header.Get("X-Webhook-Signature"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	hook := apiObject(t, http.MethodPost, base+"/api/webhooks", token, map[string]any{
		"url":         receiver.URL,
		"secret":      "topsecret",
		"events":      []string{"login"},
		"description": "login hook",
	})
	hookID, _ := hook["id"].(string)
	if hookID == "" || hook["url"] != receiver.URL {
		t.Fatalf("webhook %v", hook)
	}
	if !listHas(apiList(t, http.MethodGet, base+"/api/webhooks", token, nil), "id", hookID) {
		t.Fatal("webhook list")
	}
	if apiObject(t, http.MethodGet, base+"/api/webhooks/"+hookID, token, nil)["description"] != "login hook" {
		t.Fatal("get webhook")
	}
	patched := apiObject(t, http.MethodPatch, base+"/api/webhooks/"+hookID, token, map[string]any{
		"events":      []string{"logout"},
		"description": "logout hook",
	})
	events, _ := patched["events"].([]any)
	if patched["description"] != "logout hook" || len(events) != 1 || events[0] != "logout" {
		t.Fatalf("patch webhook %v", patched)
	}
	if apiObject(t, http.MethodPost, base+"/api/webhooks/"+hookID+"/test", token, nil)["status"] != "delivered" {
		t.Fatal("test webhook")
	}
	if len(hits) != 1 || hits[0] != "webhook.test" {
		t.Fatalf("webhook hits %v", hits)
	}
	if apiObject(t, http.MethodDelete, base+"/api/webhooks/"+hookID, token, nil)["status"] != "deleted" {
		t.Fatal("delete webhook")
	}
	missingHook, missingHookRaw := apiCall(t, http.MethodGet, base+"/api/webhooks/"+hookID, token, nil)
	if decodeObject(t, missingHook, missingHookRaw, http.StatusNotFound)["error"] != "not_found" {
		t.Fatalf("webhook remained %d %s", missingHook, missingHookRaw)
	}

	rotated := apiObject(t, http.MethodPost, base+"/api/keys/rotate", token, nil)
	if rotated["status"] != "rotated" || len(rotated["kids"].([]any)) == 0 {
		t.Fatalf("rotate %v", rotated)
	}
	jwks := apiObject(t, http.MethodGet, base+"/oidc/jwks", "", nil)
	keys, _ := jwks["keys"].([]any)
	if len(keys) == 0 {
		t.Fatalf("jwks %v", jwks)
	}
	foundKid := false
	for _, kid := range rotated["kids"].([]any) {
		for _, key := range keys {
			row, _ := key.(map[string]any)
			if row["kid"] == kid {
				foundKid = true
			}
		}
	}
	if !foundKid {
		t.Fatalf("rotated kids %v missing from %v", rotated["kids"], keys)
	}
	audit := apiList(t, http.MethodGet, base+"/api/audit?window=1h&action=key.rotate", token, nil)
	if len(audit) == 0 {
		t.Fatal("key rotation was not audited")
	}
}

func approveBrowserConsent(t *testing.T, base, username, password, clientID, redirectURI, scope string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := url.Values{}
	login.Set("username", username)
	login.Set("password", password)
	login.Set("csrf_token", csrfToken(t, browser, base+"/login"))
	loginResp, err := browser.PostForm(base+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("login %d", loginResp.StatusCode)
	}

	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", scope)
	query.Set("state", "mgmt")
	authResp, err := browser.Get(base + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = authResp.Body.Close()
	consentURL := authResp.Header.Get("Location")
	if authResp.StatusCode != http.StatusFound || !strings.Contains(consentURL, "/consent") {
		t.Fatalf("authorize %d %s", authResp.StatusCode, consentURL)
	}
	if strings.HasPrefix(consentURL, "/") {
		consentURL = base + consentURL
	}
	page, err := browser.Get(consentURL)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	form := url.Values{}
	form.Set("csrf_token", csrfFromBody(t, string(pageBody)))
	form.Set("action", "approve")
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("response_type", "code")
	form.Set("scope", scope)
	form.Set("state", "mgmt")
	approved, err := browser.PostForm(base+"/consent", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = approved.Body.Close()
	next := approved.Header.Get("Location")
	if approved.StatusCode != http.StatusFound {
		t.Fatalf("consent %d %s", approved.StatusCode, next)
	}
	if strings.HasPrefix(next, "/") {
		next = base + next
	}
	issued, err := browser.Get(next)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(issued.Body)
	_ = issued.Body.Close()
	loc := issued.Header.Get("Location")
	if issued.StatusCode != http.StatusFound || !strings.Contains(loc, "code=") {
		t.Fatalf("code %d %s %s", issued.StatusCode, loc, body)
	}
}

func apiObject(t *testing.T, method, rawURL, token string, payload any, want ...int) map[string]any {
	t.Helper()
	status, raw := apiCall(t, method, rawURL, token, payload)
	return decodeObject(t, status, raw, want...)
}

func apiList(t *testing.T, method, rawURL, token string, payload any) []any {
	t.Helper()
	status, raw := apiCall(t, method, rawURL, token, payload)
	return decodeList(t, status, raw)
}

func apiCall(t *testing.T, method, rawURL, token string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

func decodeObject(t *testing.T, status int, raw []byte, want ...int) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("status %d body %s", status, raw)
	}
	if len(want) > 0 && status != want[0] {
		t.Fatalf("status %d want %d body %v", status, want[0], body)
	}
	return body
}

func decodeList(t *testing.T, status int, raw []byte) []any {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("status %d body %s", status, raw)
	}
	var body []any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("status %d body %s", status, raw)
	}
	return body
}

func listHas(rows []any, key string, want any) bool {
	for _, row := range rows {
		item, _ := row.(map[string]any)
		if item[key] == want {
			return true
		}
	}
	return false
}

func listHasField(rows []any, key string, want any, field string, value any) bool {
	for _, row := range rows {
		item, _ := row.(map[string]any)
		if item[key] == want && item[field] == value {
			return true
		}
	}
	return false
}

func firstString(rows []any, key string) string {
	for _, row := range rows {
		item, _ := row.(map[string]any)
		if value, _ := item[key].(string); value != "" {
			return value
		}
	}
	return ""
}
