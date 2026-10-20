package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func TestDeviceDenyThenPoll(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)

	reg, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"TV","redirect_uris":["https://example.com/cb"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`))
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ID     string `json:"client_id"`
		Secret string `json:"client_secret"`
	}
	if err := json.NewDecoder(reg.Body).Decode(&client); err != nil {
		t.Fatal(err)
	}
	_ = reg.Body.Close()

	devReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/device", strings.NewReader("scope=openid"))
	devReq.SetBasicAuth(client.ID, client.Secret)
	devReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	devResp, err := http.DefaultClient.Do(devReq)
	if err != nil {
		t.Fatal(err)
	}
	var device map[string]any
	if err := json.NewDecoder(devResp.Body).Decode(&device); err != nil {
		t.Fatal(err)
	}
	_ = devResp.Body.Close()
	userCode, _ := device["user_code"].(string)
	deviceCode, _ := device["device_code"].(string)
	if userCode == "" || deviceCode == "" {
		t.Fatalf("device %v", device)
	}

	poll := url.Values{}
	poll.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	poll.Set("device_code", deviceCode)
	poll.Set("client_id", client.ID)
	poll.Set("client_secret", client.Secret)
	waiting, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(poll.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	waitingBody, _ := io.ReadAll(waiting.Body)
	_ = waiting.Body.Close()
	if waiting.StatusCode != http.StatusBadRequest || !strings.Contains(string(waitingBody), "authorization_pending") {
		t.Fatalf("pending %d %s", waiting.StatusCode, waitingBody)
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{}
	form.Set("username", "ada")
	form.Set("password", "correct horse")
	form.Set("csrf_token", csrfToken(t, browser, ts.URL+"/login"))
	loginResp, err := browser.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()

	page, err := browser.Get(ts.URL + "/device?user_code=" + url.QueryEscape(userCode))
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(pageBody), "TV") {
		t.Fatalf("device page %d %s", page.StatusCode, pageBody)
	}

	deny := url.Values{}
	deny.Set("user_code", userCode)
	deny.Set("action", "deny")
	deny.Set("csrf_token", csrfFromBody(t, string(pageBody)))
	denied, err := browser.PostForm(ts.URL+"/device", deny)
	if err != nil {
		t.Fatal(err)
	}
	deniedBody, _ := io.ReadAll(denied.Body)
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusOK || !strings.Contains(string(deniedBody), "denied") {
		t.Fatalf("deny %d %s", denied.StatusCode, deniedBody)
	}

	pollResp, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(poll.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pollResp.Body.Close() }()
	raw, _ := io.ReadAll(pollResp.Body)
	if pollResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "access_denied") {
		t.Fatalf("poll %d %s", pollResp.StatusCode, raw)
	}
}
