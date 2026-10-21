package integration

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func TestAccountAPIAndResetPages(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	base := ts.URL
	mgmt := managementAccessToken(t, base)
	user := apiObject(t, http.MethodPost, base+"/api/users", mgmt, map[string]any{
		"username": "ada",
		"password": "correct horse",
		"email":    "ada@example.com",
	}, http.StatusCreated)
	if user["id"] == "" {
		t.Fatalf("user %v", user)
	}
	client := createAPIClient(t, base, mgmt, map[string]any{
		"name":                       "Notes",
		"redirect_uris":              []string{"https://app.example/cb"},
		"grant_types":                []string{"password", "refresh_token"},
		"scopes":                     []string{"openid", "profile", "email"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	consented := createAPIClient(t, base, mgmt, map[string]any{
		"name":                       "Browser",
		"redirect_uris":              []string{"https://browser.example/cb"},
		"grant_types":                []string{"authorization_code"},
		"scopes":                     []string{"openid", "profile"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	clientID := client["id"].(string)
	granted, grantBody := postForm(t, base+"/oauth/token", clientID, client["secret"].(string), url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"correct horse"},
		"scope":      {"openid"},
	})
	if granted != http.StatusOK {
		t.Fatalf("grant %d %v", granted, grantBody)
	}
	userToken := grantBody["access_token"].(string)

	me := apiObject(t, http.MethodGet, base+"/api/me", userToken, nil)
	if me["username"] != "ada" || me["mfa_enabled"] != false {
		t.Fatalf("me %v", me)
	}

	consentID := consented["id"].(string)
	approveBrowserConsent(t, base, "ada", "correct horse", consentID, "https://browser.example/cb", "openid profile")
	consents := apiList(t, http.MethodGet, base+"/api/me/consents", userToken, nil)
	if !listHas(consents, "ClientID", consentID) {
		t.Fatalf("consents %v", consents)
	}
	if apiObject(t, http.MethodDelete, base+"/api/me/consents/"+url.PathEscape(consentID), userToken, nil)["status"] != "revoked" {
		t.Fatal("revoke consent")
	}
	if listHas(apiList(t, http.MethodGet, base+"/api/me/consents", userToken, nil), "ClientID", consentID) {
		t.Fatal("consent remained")
	}

	sessions := apiList(t, http.MethodGet, base+"/api/me/sessions", userToken, nil)
	if firstString(sessions, "id") == "" {
		t.Fatalf("sessions %v", sessions)
	}
	refresh := apiList(t, http.MethodGet, base+"/api/me/refresh-tokens", userToken, nil)
	if firstString(refresh, "id") == "" || listHas(refresh, "token", grantBody["refresh_token"].(string)) {
		t.Fatalf("refresh %v", refresh)
	}
	if !listHas(apiList(t, http.MethodGet, base+"/api/me/activity", userToken, nil), "success", true) {
		t.Fatal("activity")
	}

	patched := apiObject(t, http.MethodPatch, base+"/api/me", userToken, map[string]any{"email": "ada-new@example.com"})
	if patched["email"] != "ada-new@example.com" || patched["email_verified"] != false {
		t.Fatalf("patch %v", patched)
	}
	sendStatus, sendRaw := apiCall(t, http.MethodPost, base+"/api/me/email/send", userToken, nil)
	if apiObjectFrom(t, sendStatus, sendRaw, http.StatusServiceUnavailable)["error"] != "mailer_disabled" {
		t.Fatalf("resend %d %s", sendStatus, sendRaw)
	}

	wrongStatus, wrongRaw := apiCall(t, http.MethodPost, base+"/api/me/password", userToken, map[string]any{
		"current_password": "wrong horse",
		"new_password":     "brand new horse",
	})
	if apiObjectFrom(t, wrongStatus, wrongRaw, http.StatusBadRequest)["error"] != "invalid_request" {
		t.Fatalf("wrong password %d %s", wrongStatus, wrongRaw)
	}
	if apiObject(t, http.MethodPost, base+"/api/me/password", userToken, map[string]any{
		"current_password": "correct horse",
		"new_password":     "brand new horse",
	})["status"] != "ok" {
		t.Fatal("change password")
	}
	oldStatus, _ := postForm(t, base+"/oauth/token", clientID, client["secret"].(string), url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"correct horse"},
	})
	if oldStatus == http.StatusOK {
		t.Fatal("old password still works")
	}
	if apiObject(t, http.MethodGet, base+"/api/me", userToken, nil)["username"] != "ada" {
		t.Fatal("access token died with the password change")
	}

	browser := browserClient()
	forgotPage, err := browser.Get(base + "/forgot")
	if err != nil {
		t.Fatal(err)
	}
	forgotBody := readBody(t, forgotPage)
	if forgotPage.StatusCode != http.StatusOK || !strings.Contains(forgotBody, "Send reset link") {
		t.Fatalf("forgot %d %s", forgotPage.StatusCode, forgotBody)
	}
	forgot := url.Values{}
	forgot.Set("csrf_token", csrfFromBody(t, forgotBody))
	forgot.Set("username", "ada")
	forgotResp, err := browser.PostForm(base+"/forgot", forgot)
	if err != nil {
		t.Fatal(err)
	}
	forgotSent := readBody(t, forgotResp)
	if !strings.Contains(forgotSent, "not configured") {
		t.Fatalf("forgot submit %s", forgotSent)
	}

	resetPage, err := browser.Get(base + "/reset?token=bad-token")
	if err != nil {
		t.Fatal(err)
	}
	resetBody := readBody(t, resetPage)
	if !strings.Contains(resetBody, "bad-token") {
		t.Fatalf("reset page %s", resetBody)
	}
	reset := url.Values{}
	reset.Set("csrf_token", csrfFromBody(t, resetBody))
	reset.Set("token", "bad-token")
	reset.Set("password", "brand new horse")
	resetResp, err := browser.PostForm(base+"/reset", reset)
	if err != nil {
		t.Fatal(err)
	}
	resetResult := readBody(t, resetResp)
	if !strings.Contains(resetResult, "invalid or has already been used") {
		t.Fatalf("reset submit %s", resetResult)
	}

	verify, err := http.Get(base + "/verify-email?token=bad-token")
	if err != nil {
		t.Fatal(err)
	}
	verifyBody := readBody(t, verify)
	if !strings.Contains(verifyBody, "invalid or has already been used") {
		t.Fatalf("verify %s", verifyBody)
	}
}

func apiObjectFrom(t *testing.T, status int, raw []byte, want int) map[string]any {
	t.Helper()
	return decodeObject(t, status, raw, want)
}

func browserClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
