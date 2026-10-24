package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/background"
)

func csrfFromBody(t *testing.T, body string) string {
	t.Helper()
	return formValue(t, body, "csrf_token")
}

func formValue(t *testing.T, body, name string) string {
	t.Helper()
	key := `name="` + name + `" value="`
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("%s field missing: %s", name, body)
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("%s field truncated", name)
	}
	return rest[:j]
}

func csrfToken(t *testing.T, browser *http.Client, page string) string {
	t.Helper()
	resp, err := browser.Get(page)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return csrfFromBody(t, string(body))
}

func managementAccessToken(t *testing.T, base string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader("grant_type=client_credentials&scope=management"))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("test-mgmt", "test-mgmt-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("management token status %d: %v", resp.StatusCode, body)
	}
	token, _ := body["access_token"].(string)
	if token == "" {
		t.Fatal("empty management token")
	}
	return token
}

func TestManagementAPIRequiresClientCredentials(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/api/users")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+managementAccessToken(t, ts.URL))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status %d", resp.StatusCode)
	}
}

func TestDynamicRegistrationStripsManagementScope(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"Nope","redirect_uris":["https://example.com/cb"],"grant_types":["client_credentials"],"scope":"management openid"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	scope, _ := body["scope"].(string)
	if strings.Contains(scope, "management") {
		t.Fatalf("scope %q", scope)
	}

	tokenReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader("grant_type=client_credentials&scope=not-a-scope"))
	tokenReq.SetBasicAuth("test-mgmt", "test-mgmt-secret")
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tokenResp.Body.Close() }()
	raw, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_scope") {
		t.Fatalf("status %d body %s", tokenResp.StatusCode, raw)
	}
}

func TestDeviceApprovalUsesSession(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)

	createUser(t, ts.URL, token)
	reg, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"TV","redirect_uris":["https://example.com/cb"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scope":"openid profile","token_endpoint_auth_method":"client_secret_basic"}`))
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

	noRedirect := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	anon, err := noRedirect.Get(ts.URL + "/device?user_code=" + url.QueryEscape(userCode))
	if err != nil {
		t.Fatal(err)
	}
	_ = anon.Body.Close()
	if anon.StatusCode != http.StatusFound || !strings.Contains(anon.Header.Get("Location"), "/login") {
		t.Fatalf("device status %d location %s", anon.StatusCode, anon.Header.Get("Location"))
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
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

	approve := url.Values{}
	approve.Set("user_code", userCode)
	approve.Set("action", "approve")
	approve.Set("user_id", "someone-else")
	approve.Set("csrf_token", csrfFromBody(t, string(pageBody)))
	ok, err := browser.PostForm(ts.URL+"/device", approve)
	if err != nil {
		t.Fatal(err)
	}
	_ = ok.Body.Close()

	poll := url.Values{}
	poll.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	poll.Set("device_code", deviceCode)
	poll.Set("client_id", client.ID)
	poll.Set("client_secret", client.Secret)
	pollResp, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(poll.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pollResp.Body.Close() }()
	var issued map[string]any
	if err := json.NewDecoder(pollResp.Body).Decode(&issued); err != nil {
		t.Fatal(err)
	}
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("poll %d %v", pollResp.StatusCode, issued)
	}
	access, _ := issued["access_token"].(string)
	me, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
	me.Header.Set("Authorization", "Bearer "+access)
	meResp, err := http.DefaultClient.Do(me)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meResp.Body.Close() }()
	var profile map[string]any
	_ = json.NewDecoder(meResp.Body).Decode(&profile)
	if profile["username"] != "ada" {
		t.Fatalf("profile %v", profile)
	}
}

func TestRefreshFamilyReuse(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)

	reg, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"App","redirect_uris":["https://example.com/cb"],"grant_types":["password","refresh_token"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ID     string `json:"client_id"`
		Secret string `json:"client_secret"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&client)
	_ = reg.Body.Close()

	first := passwordToken(t, ts.URL, client.ID, client.Secret, "correct horse")
	second := passwordToken(t, ts.URL, client.ID, client.Secret, "correct horse")
	rotated := refreshToken(t, ts.URL, client.ID, client.Secret, first["refresh_token"].(string))
	reused := refreshRaw(t, ts.URL, client.ID, client.Secret, first["refresh_token"].(string))
	if reused.StatusCode == http.StatusOK {
		t.Fatal("reused refresh token was accepted")
	}
	_ = reused.Body.Close()
	dead := refreshRaw(t, ts.URL, client.ID, client.Secret, rotated["refresh_token"].(string))
	deadBody, _ := io.ReadAll(dead.Body)
	_ = dead.Body.Close()
	if dead.StatusCode == http.StatusOK {
		t.Fatalf("family was not revoked: %s", deadBody)
	}
	still := refreshRaw(t, ts.URL, client.ID, client.Secret, second["refresh_token"].(string))
	var stillBody map[string]any
	if err := json.NewDecoder(still.Body).Decode(&stillBody); err != nil {
		t.Fatal(err)
	}
	_ = still.Body.Close()
	if still.StatusCode != http.StatusOK {
		t.Fatalf("other family failed: %d %v", still.StatusCode, stillBody)
	}

	meReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me/refresh-tokens", nil)
	meReq.Header.Set("Authorization", "Bearer "+stillBody["access_token"].(string))
	meResp, err := http.DefaultClient.Do(meReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = meResp.Body.Close() }()
	raw, _ := io.ReadAll(meResp.Body)
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh list %d %s", meResp.StatusCode, raw)
	}
	if strings.Contains(string(raw), second["refresh_token"].(string)) {
		t.Fatalf("refresh secret leaked: %s", raw)
	}
}

func TestBackChannelLogout(t *testing.T) {
	var got url.Values
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		w.WriteHeader(http.StatusOK)
	}))
	defer rp.Close()

	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)

	body := `{"client_name":"RP","redirect_uris":["https://example.com/cb"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"scope":"openid","backchannel_logout_uri":"` + rp.URL + `","post_logout_redirect_uris":["https://example.com/done"]}`
	reg, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ID     string `json:"client_id"`
		Secret string `json:"client_secret"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&client)
	_ = reg.Body.Close()

	devReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/device", strings.NewReader("scope=openid"))
	devReq.SetBasicAuth(client.ID, client.Secret)
	devReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	devResp, err := http.DefaultClient.Do(devReq)
	if err != nil {
		t.Fatal(err)
	}
	var device map[string]any
	_ = json.NewDecoder(devResp.Body).Decode(&device)
	_ = devResp.Body.Close()

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct horse")
	login.Set("csrf_token", csrfToken(t, browser, ts.URL+"/login"))
	loginResp, err := browser.PostForm(ts.URL+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()
	approve := url.Values{}
	approve.Set("user_code", device["user_code"].(string))
	approve.Set("action", "approve")
	approve.Set("csrf_token", csrfToken(t, browser, ts.URL+"/device?user_code="+url.QueryEscape(device["user_code"].(string))))
	ok, err := browser.PostForm(ts.URL+"/device", approve)
	if err != nil {
		t.Fatal(err)
	}
	_ = ok.Body.Close()

	logoutForm := url.Values{"confirm": {"yes"}}
	logoutForm.Set("csrf_token", csrfToken(t, browser, ts.URL+"/oauth/logout"))
	logout, err := browser.PostForm(ts.URL+"/oauth/logout", logoutForm)
	if err != nil {
		t.Fatal(err)
	}
	_ = logout.Body.Close()
	if got.Get("logout_token") == "" {
		t.Fatal("back-channel logout was not delivered")
	}
	parts := strings.Split(got.Get("logout_token"), ".")
	if len(parts) != 3 {
		t.Fatalf("logout token %q", got.Get("logout_token"))
	}

	disc, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = disc.Body.Close() }()
	var meta map[string]any
	_ = json.NewDecoder(disc.Body).Decode(&meta)
	if meta["end_session_endpoint"] == nil || meta["backchannel_logout_supported"] != true {
		t.Fatalf("discovery %v", meta["end_session_endpoint"])
	}
}

func TestWebhookFiresOnlyForSelectedEvents(t *testing.T) {
	var mu sync.Mutex
	var events []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		events = append(events, r.Header.Get("X-Webhook-Event"))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()

	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)
	createHook(t, ts.URL, token, receiver.URL, []string{"login"})
	createHook(t, ts.URL, token, receiver.URL, []string{"logout"})

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct horse")
	login.Set("csrf_token", csrfToken(t, browser, ts.URL+"/login"))
	resp, err := browser.PostForm(ts.URL+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	waitEvents(t, &mu, &events, "login")

	outForm := url.Values{"confirm": {"yes"}}
	outForm.Set("csrf_token", csrfToken(t, browser, ts.URL+"/oauth/logout"))
	out, err := browser.PostForm(ts.URL+"/oauth/logout", outForm)
	if err != nil {
		t.Fatal(err)
	}
	_ = out.Body.Close()
	waitEvents(t, &mu, &events, "login,logout")
}

func waitEvents(t *testing.T, mu *sync.Mutex, events *[]string, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		mu.Lock()
		got = strings.Join(*events, ",")
		mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("events %q, want %q", got, want)
}

func createHook(t *testing.T, base, token, hookURL string, events []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"url": hookURL, "events": events, "secret": "topsecret"})
	req, err := http.NewRequest(http.MethodPost, base+"/api/webhooks", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create webhook %d %s", resp.StatusCode, raw)
	}
}

func TestLoginAnalyticsEndpoint(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)
	reg, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"Analytics","redirect_uris":["https://example.com/cb"],"grant_types":["password"]}`))
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
	bad := url.Values{}
	bad.Set("grant_type", "password")
	bad.Set("username", "ada")
	bad.Set("password", "wrong")
	bad.Set("client_id", client.ID)
	bad.Set("client_secret", client.Secret)
	badResp, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(bad.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode == http.StatusOK {
		t.Fatal("wrong password was accepted")
	}
	issued := passwordToken(t, ts.URL, client.ID, client.Secret, "correct horse")
	background.Wait()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me/login-analytics?window=24h", nil)
	req.Header.Set("Authorization", "Bearer "+issued["access_token"].(string))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var report map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("analytics %d %v", resp.StatusCode, report)
	}
	if report["successes"].(float64) < 1 || report["failures"].(float64) < 1 || report["unique_ips"].(float64) < 1 {
		t.Fatalf("%v", report)
	}
}

func TestForgotPasswordWithoutSMTP(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	resp, err := http.Post(ts.URL+"/api/account/password/forgot", "application/json", strings.NewReader(`{"username":"missing"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func createUser(t *testing.T, base, token string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/users", strings.NewReader(`{"username":"ada","password":"correct horse","email":"ada@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create user %d %s", resp.StatusCode, body)
	}
}

func passwordToken(t *testing.T, base, id, secret, password string) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "ada")
	form.Set("password", password)
	form.Set("client_id", id)
	form.Set("client_secret", secret)
	resp, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password grant %d %v", resp.StatusCode, body)
	}
	return body
}

func refreshToken(t *testing.T, base, id, secret, refresh string) map[string]any {
	t.Helper()
	resp := refreshRaw(t, base, id, secret, refresh)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh %d %v", resp.StatusCode, body)
	}
	return body
}

func refreshRaw(t *testing.T, base, id, secret, refresh string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	form.Set("client_id", id)
	form.Set("client_secret", secret)
	resp, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
