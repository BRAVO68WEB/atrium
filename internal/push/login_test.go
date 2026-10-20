package push_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/service"
)

func TestPushLoginApprovesAndDeniesCIBA(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Push.Enabled = true
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	ts := newServer(t, cfg)
	token := managementToken(t, ts.URL)
	createUser(t, ts.URL, token)
	browser := signIn(t, ts.URL)
	dpop := service.NewDPoPService()
	key, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	registered := registerDevice(t, ts, browser, dpop, key, []string{"boolean"})
	if registered.Status != http.StatusCreated {
		t.Fatalf("register %d %s", registered.Status, registered.Body)
	}

	client := createPushClient(t, ts.URL, token)
	authReqID := pushCIBA(t, ts.URL, client, "ada", "42")

	page, err := browser.Get(ts.URL + "/push/approve")
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	text := string(pageBody)
	if page.StatusCode != http.StatusOK || !strings.Contains(text, "42") || !strings.Contains(text, authReqID) {
		t.Fatalf("approve page %d %s", page.StatusCode, text)
	}
	form := url.Values{}
	form.Set("csrf_token", attr(t, text, "csrf_token"))
	form.Set("auth_req_id", authReqID)
	form.Set("action", "approve")
	approved, err := browser.PostForm(ts.URL+"/push/approve", form)
	if err != nil {
		t.Fatal(err)
	}
	approvedBody, _ := io.ReadAll(approved.Body)
	_ = approved.Body.Close()
	if approved.StatusCode != http.StatusOK || !strings.Contains(string(approvedBody), "push-approved") {
		t.Fatalf("approve %d %s", approved.StatusCode, approvedBody)
	}
	granted := pushPoll(t, ts.URL, client, authReqID)
	if granted.Status != http.StatusOK || !strings.Contains(granted.Body, "access_token") {
		t.Fatalf("poll %d %s", granted.Status, granted.Body)
	}

	second := pushCIBA(t, ts.URL, client, "ada", "99")
	again, err := browser.Get(ts.URL + "/push/approve")
	if err != nil {
		t.Fatal(err)
	}
	againBody, _ := io.ReadAll(again.Body)
	_ = again.Body.Close()
	deny := url.Values{}
	deny.Set("csrf_token", attr(t, string(againBody), "csrf_token"))
	deny.Set("auth_req_id", second)
	deny.Set("action", "deny")
	denied, err := browser.PostForm(ts.URL+"/push/approve", deny)
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusOK {
		t.Fatalf("deny %d", denied.StatusCode)
	}
	blocked := pushPoll(t, ts.URL, client, second)
	if blocked.Status != http.StatusBadRequest || !strings.Contains(blocked.Body, "access_denied") {
		t.Fatalf("denied poll %d %s", blocked.Status, blocked.Body)
	}
}

func createPushClient(t *testing.T, base, token string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"name":                       "TV",
		"redirect_uris":              []string{"https://tv.example/cb"},
		"grant_types":                []string{"urn:openid:params:grant-type:ciba"},
		"scopes":                     []string{"openid"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	res := postJSON(t, base+"/api/clients", string(raw), token)
	if res.Status != http.StatusCreated {
		t.Fatalf("client %d %s", res.Status, res.Body)
	}
	var client map[string]any
	if err := json.Unmarshal([]byte(res.Body), &client); err != nil {
		t.Fatal(err)
	}
	return client
}

func pushCIBA(t *testing.T, base string, client map[string]any, loginHint, binding string) string {
	t.Helper()
	form := url.Values{}
	form.Set("login_hint", loginHint)
	form.Set("scope", "openid")
	form.Set("binding_message", binding)
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client["id"].(string), client["secret"].(string))
	res := do(t, req)
	if res.Status != http.StatusOK {
		t.Fatalf("bc-authorize %d %s", res.Status, res.Body)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(res.Body), &body); err != nil {
		t.Fatal(err)
	}
	id, _ := body["auth_req_id"].(string)
	if id == "" {
		t.Fatalf("bc-authorize %v", body)
	}
	return id
}

func pushPoll(t *testing.T, base string, client map[string]any, authReqID string) httpResult {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "urn:openid:params:grant-type:ciba")
	form.Set("auth_req_id", authReqID)
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(client["id"].(string)+":"+client["secret"].(string))))
	return do(t, req)
}
