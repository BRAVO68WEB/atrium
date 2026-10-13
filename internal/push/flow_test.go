package push_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/server"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/testpg"
	"github.com/golang-jwt/jwt/v5"
)

func TestPushStaysOffAndDeviceGrantRemains(t *testing.T) {
	ts := newServer(t, config.DefaultConfig())
	resp, err := http.Get(ts.URL + "/.well-known/oauth-push-notification")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("discovery %d", resp.StatusCode)
	}
	reg := postJSON(t, ts.URL+"/oauth/register", `{"client_name":"TV","redirect_uris":["https://tv.example/cb"],"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],"token_endpoint_auth_method":"none"}`, "")
	if reg.Status != http.StatusCreated {
		t.Fatalf("register %d %s", reg.Status, reg.Body)
	}
	var client map[string]any
	_ = json.Unmarshal([]byte(reg.Body), &client)
	form := url.Values{}
	form.Set("client_id", client["client_id"].(string))
	device := postForm(t, ts.URL+"/oauth/device", form, nil)
	if device.Status != http.StatusOK || !strings.Contains(device.Body, "device_code") {
		t.Fatalf("device %d %s", device.Status, device.Body)
	}
}

func TestPushRegistrationLifecycle(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Push.Enabled = true
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	ts := newServer(t, cfg)
	doc := getJSON(t, ts.URL+"/.well-known/oauth-push-notification")
	if _, ok := doc["push_relay_endpoint"]; ok {
		t.Fatalf("relay advertised %v", doc["push_relay_endpoint"])
	}
	if doc["registration_endpoint"] != "http://localhost:8080/push/register" || doc["delivery_modes_supported"].([]any)[0] != "poll" {
		t.Fatalf("discovery %v", doc)
	}

	token := managementToken(t, ts.URL)
	createUser(t, ts.URL, token)
	browser := signIn(t, ts.URL)
	dpop := service.NewDPoPService()
	key, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	first := registerDevice(t, ts, browser, dpop, key, []string{"boolean"})
	replay := registerRaw(t, ts.URL, first.Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), []string{"boolean"})
	if replay.Status != http.StatusBadRequest || !strings.Contains(replay.Body, "registration_token_already_used") {
		t.Fatalf("replay %d %s", replay.Status, replay.Body)
	}
	weak := registerDevice(t, ts, browser, dpop, key, []string{"input_manual"})
	if weak.Status != http.StatusBadRequest || !strings.Contains(weak.Body, "interaction_type_unsupported") {
		t.Fatalf("ceremony %d %s", weak.Status, weak.Body)
	}

	list := getAuth(t, browser, ts.URL+"/push/devices")
	if list.Status != http.StatusOK || strings.Contains(list.Body, first.Credential) || !strings.Contains(list.Body, first.DeviceID) {
		t.Fatalf("list %d %s", list.Status, list.Body)
	}

	revoked := revokeDevice(t, ts.URL, dpop, key, first.DeviceID, first.Credential, "")
	if revoked.Status != http.StatusNoContent || revoked.Header.Get("Replay-Nonce") == "" {
		t.Fatalf("revoke %d nonce %q %s", revoked.Status, revoked.Header.Get("Replay-Nonce"), revoked.Body)
	}
	again := revokeDevice(t, ts.URL, dpop, key, first.DeviceID, first.Credential, "")
	if again.Status != http.StatusUnauthorized {
		t.Fatalf("second revoke %d %s", again.Status, again.Body)
	}

	secondKey, _ := dpop.GenerateKeyPair()
	second := registerDevice(t, ts, browser, dpop, secondKey, []string{"boolean", "number_choose"})
	rotated, nonce := rotateDevice(t, ts.URL, dpop, secondKey, second)
	if rotated.Status != http.StatusOK || nonce == "" {
		t.Fatalf("rotate %d nonce %q %s", rotated.Status, nonce, rotated.Body)
	}
	var next map[string]any
	_ = json.Unmarshal([]byte(rotated.Body), &next)
	newCredential, _ := next["device_credential"].(string)
	missing := rotateAgain(t, ts.URL, dpop, second.NewKey, second.DeviceID, newCredential, "")
	if missing.Status != http.StatusBadRequest || !strings.Contains(missing.Body, "nonce_replayed") {
		t.Fatalf("nonce %d %s", missing.Status, missing.Body)
	}
}

func TestPushExpiredTokenAndDeviceLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Push.Enabled = true
	cfg.Push.RegistrationTokenTTL = 1
	cfg.Push.MaxDevicesPerUser = 1
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	ts := newServer(t, cfg)
	token := managementToken(t, ts.URL)
	createUser(t, ts.URL, token)
	browser := signIn(t, ts.URL)
	dpop := service.NewDPoPService()
	key, _ := dpop.GenerateKeyPair()
	page := enroll(t, browser, ts.URL)
	time.Sleep(1100 * time.Millisecond)
	expired := registerRaw(t, ts.URL, page.Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), []string{"boolean"})
	if expired.Status != http.StatusBadRequest || !strings.Contains(expired.Body, "registration_token_expired") {
		t.Fatalf("expired %d %s", expired.Status, expired.Body)
	}

	cfg.Push.RegistrationTokenTTL = 300
	fresh := newServer(t, cfg)
	token = managementToken(t, fresh.URL)
	createUser(t, fresh.URL, token)
	browser = signIn(t, fresh.URL)
	ok := registerDevice(t, fresh, browser, dpop, key, []string{"boolean"})
	if ok.Status != http.StatusCreated {
		t.Fatalf("first %d %s", ok.Status, ok.Body)
	}
	key2, _ := dpop.GenerateKeyPair()
	limited := registerDevice(t, fresh, browser, dpop, key2, []string{"boolean"})
	if limited.Status != http.StatusForbidden || !strings.Contains(limited.Body, "device_limit") {
		t.Fatalf("limit %d %s", limited.Status, limited.Body)
	}
}

type enrolled struct {
	Token      string
	DeviceID   string
	Credential string
	Status     int
	Body       string
	NewKey     *ecdsa.PrivateKey
}

type httpResult struct {
	Status int
	Body   string
	Header http.Header
}

func newServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	srv, err := server.New(cfg, testpg.Open(t), queue.NewMemoryQueue(4))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.GetRouter())
	t.Cleanup(ts.Close)
	return ts
}

func managementToken(t *testing.T, base string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "management")
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	req.SetBasicAuth("test-mgmt", "test-mgmt-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	token, _ := body["access_token"].(string)
	if resp.StatusCode != http.StatusOK || token == "" {
		t.Fatalf("management token %d %v", resp.StatusCode, body)
	}
	return token
}

func createUser(t *testing.T, base, token string) {
	t.Helper()
	res := postJSON(t, base+"/api/users", `{"username":"ada","password":"correct horse","email":"ada@example.com","email_verified":true}`, token)
	if res.Status != http.StatusCreated {
		t.Fatalf("user %d %s", res.Status, res.Body)
	}
}

func signIn(t *testing.T, base string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	page, err := browser.Get(base + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	form := url.Values{}
	form.Set("csrf_token", attr(t, string(body), "csrf_token"))
	form.Set("username", "ada")
	form.Set("password", "correct horse")
	resp, err := browser.PostForm(base+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return browser
}

func enroll(t *testing.T, browser *http.Client, base string) enrolled {
	t.Helper()
	resp, err := browser.Get(base + "/push/enroll")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll %d %s", resp.StatusCode, body)
	}
	text := string(body)
	if !strings.Contains(text, "enroll-qr") || !strings.Contains(text, "/push/enroll#") {
		t.Fatalf("page missing qr %s", text)
	}
	return enrolled{Token: attrText(t, text, "registration-token")}
}

func registerDevice(t *testing.T, ts *httptest.Server, browser *http.Client, dpop *service.DPoPService, key *ecdsa.PrivateKey, types []string) enrolled {
	t.Helper()
	page := enroll(t, browser, ts.URL)
	res := registerRaw(t, ts.URL, page.Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), types)
	var body map[string]any
	_ = json.Unmarshal([]byte(res.Body), &body)
	return enrolled{
		Token:      page.Token,
		DeviceID:   str(body["device_id"]),
		Credential: str(body["device_credential"]),
		Status:     res.Status,
		Body:       res.Body,
		NewKey:     key,
	}
}

func registerRaw(t *testing.T, base, token string, jwk map[string]any, types []string) httpResult {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"registration_token": token,
		"public_key":         jwk,
		"interaction_types":  types,
		"platform":           "test",
	})
	return postJSON(t, base+"/push/register", string(payload), "")
}

func revokeDevice(t *testing.T, base string, dpop *service.DPoPService, key *ecdsa.PrivateKey, id, credential, nonce string) httpResult {
	t.Helper()
	form := url.Values{}
	form.Set("device_id", id)
	form.Set("token", credential)
	proof, err := dpop.CreateDPoPProof(key, http.MethodPost, base+"/push/revoke", "")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/push/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	if nonce != "" {
		req.Header.Set("Replay-Nonce", nonce)
	}
	return do(t, req)
}

func rotateDevice(t *testing.T, base string, dpop *service.DPoPService, old *ecdsa.PrivateKey, current enrolled) (httpResult, string) {
	t.Helper()
	next, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := dpop.GetPublicKeyThumbprint(&next.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	proofToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"jkt": jkt})
	proof, err := proofToken.SignedString(old)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"device_id":           current.DeviceID,
		"new_public_key":      dpop.ExportPublicKeyAsJWK(&next.PublicKey),
		"proof_of_possession": proof,
	})
	dpopProof, err := dpop.CreateDPoPProof(old, http.MethodPost, base+"/push/rotate-key", "")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/push/rotate-key", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+current.Credential)
	req.Header.Set("DPoP", dpopProof)
	res := do(t, req)
	current.NewKey = next
	return res, res.Header.Get("Replay-Nonce")
}

func rotateAgain(t *testing.T, base string, dpop *service.DPoPService, key *ecdsa.PrivateKey, id, credential, nonce string) httpResult {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"device_id": id, "new_public_key": dpop.ExportPublicKeyAsJWK(&key.PublicKey), "proof_of_possession": "nope"})
	proof, err := dpop.CreateDPoPProof(key, http.MethodPost, base+"/push/rotate-key", "")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/push/rotate-key", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("DPoP", proof)
	if nonce != "" {
		req.Header.Set("Replay-Nonce", nonce)
	}
	return do(t, req)
}

func getJSON(t *testing.T, rawURL string) map[string]any {
	t.Helper()
	res := getAuth(t, http.DefaultClient, rawURL)
	if res.Status != http.StatusOK {
		t.Fatalf("%s %d %s", rawURL, res.Status, res.Body)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(res.Body), &out)
	return out
}

func getAuth(t *testing.T, client *http.Client, rawURL string) httpResult {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return httpResult{Status: resp.StatusCode, Body: string(body), Header: resp.Header}
}

func postJSON(t *testing.T, rawURL, payload, bearer string) httpResult {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return do(t, req)
}

func postForm(t *testing.T, rawURL string, form url.Values, header http.Header) httpResult {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, values := range header {
		for _, value := range values {
			req.Header.Add(k, value)
		}
	}
	return do(t, req)
}

func do(t *testing.T, req *http.Request) httpResult {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return httpResult{Status: resp.StatusCode, Body: string(body), Header: resp.Header}
}

func attr(t *testing.T, body, name string) string {
	t.Helper()
	needle := `name="` + name + `" value="`
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatalf("missing %s", name)
	}
	rest := body[i+len(needle):]
	return rest[:strings.Index(rest, `"`)]
}

func attrText(t *testing.T, body, id string) string {
	t.Helper()
	needle := `id="` + id + `"`
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatalf("missing %s", id)
	}
	rest := body[i:]
	open := strings.Index(rest, ">")
	closeIdx := strings.Index(rest[open:], "</")
	return strings.TrimSpace(rest[open+1 : open+closeIdx])
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
