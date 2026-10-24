package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/server"
	"github.com/bravo68web/oauth-impl/internal/testpg"
	"github.com/bravo68web/oauth-impl/internal/version"
)

func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	db := testpg.Open(t)

	cfg := config.DefaultConfig()
	cfg.Security.RequirePKCE = false
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"

	q := queue.NewMemoryQueue(100)

	srv, err := server.New(cfg, db, q)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ts := httptest.NewServer(srv.GetRouter())

	cleanup := func() {
		ts.Close()
		_ = srv.Stop()
	}

	return ts, cleanup
}

func setupConfigured(t *testing.T, mutate func(*config.Config)) *httptest.Server {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Security.RequirePKCE = false
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	if mutate != nil {
		mutate(cfg)
	}
	srv, err := server.New(cfg, testpg.Open(t), queue.NewMemoryQueue(100))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.GetRouter())
	t.Cleanup(func() { _ = srv.Stop() })
	t.Cleanup(ts.Close)
	return ts
}

func setupBound(t *testing.T, mutate func(*config.Config)) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()
	cfg := config.DefaultConfig()
	cfg.Security.RequirePKCE = false
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Security.Issuer = issuer
	cfg.OIDC.Issuer = issuer
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	if mutate != nil {
		mutate(cfg)
	}
	srv, err := server.New(cfg, testpg.Open(t), queue.NewMemoryQueue(100))
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.GetRouter())
	if err := ts.Listener.Close(); err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	ts.Listener = ln
	ts.Start()
	t.Cleanup(func() { _ = srv.Stop() })
	t.Cleanup(ts.Close)
	if ts.URL != issuer {
		t.Fatalf("url %s issuer %s", ts.URL, issuer)
	}
	return ts
}

func TestHealthEndpoint(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %q", result["status"])
	}
}

func TestVersionEndpoint(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/version")
	if err != nil {
		t.Fatalf("Failed to get version: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	info := version.Current()
	if result["version"] != info.Version || result["commit"] != info.Commit || result["date"] != info.Date {
		t.Fatalf("got %#v", result)
	}
}

func TestClientRegistration(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	body := map[string]interface{}{
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"authorization_code"},
		"scope":         "openid profile",
	}

	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result["client_id"] == nil {
		t.Error("Expected client_id in response")
	}
	if result["client_secret"] == nil {
		t.Error("Expected client_secret in response")
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	regBody := map[string]interface{}{
		"client_name":   "M2M Client",
		"redirect_uris": []string{"https://example.com/callback"},
		"grant_types":   []string{"client_credentials"},
		"scope":         "openid",
	}

	jsonBody, _ := json.Marshal(regBody)
	regResp, _ := http.Post(ts.URL+"/oauth/register", "application/json", bytes.NewBuffer(jsonBody))

	var client map[string]interface{}
	if err := json.NewDecoder(regResp.Body).Decode(&client); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	func() { _ = regResp.Body.Close() }()

	clientID := client["client_id"].(string)
	clientSecret := client["client_secret"].(string)

	tokenBody := "grant_type=client_credentials&scope=openid"
	req, _ := http.NewRequest("POST", ts.URL+"/oauth/token", bytes.NewBufferString(tokenBody))
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	defer func() { _ = tokenResp.Body.Close() }()

	if tokenResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", tokenResp.StatusCode)
	}

	var token map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if token["access_token"] == nil {
		t.Error("Expected access_token in response")
	}
	if token["token_type"] != "Bearer" {
		t.Errorf("Expected token_type 'Bearer', got %q", token["token_type"])
	}
}

func TestOIDCDiscovery(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Failed to get discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	requiredFields := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"registration_endpoint",
	}

	for _, field := range requiredFields {
		if discovery[field] == nil {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

func TestJWKSEndpoint(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	resp, err := http.Get(ts.URL + "/oidc/jwks")
	if err != nil {
		t.Fatalf("Failed to get JWKS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		t.Fatal("Expected keys array in JWKS")
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}
}

func TestPasswordGrantUsesHasher(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	userReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/users", strings.NewReader(`{"username":"ada","password":"correct horse","email":"ada@example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	userReq.Header.Set("Content-Type", "application/json")
	userReq.Header.Set("Authorization", "Bearer "+managementAccessToken(t, ts.URL))
	userResp, err := http.DefaultClient.Do(userReq)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	userBody, _ := io.ReadAll(userResp.Body)
	_ = userResp.Body.Close()
	if userResp.StatusCode != http.StatusCreated {
		t.Fatalf("create user status %d: %s", userResp.StatusCode, userBody)
	}

	regResp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"Password App","redirect_uris":["https://example.com/cb"],"grant_types":["password"]}`))
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	var client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&client); err != nil {
		t.Fatalf("decode client: %v", err)
	}
	_ = regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("register status %d", regResp.StatusCode)
	}

	token := func(password string) (*http.Response, []byte) {
		t.Helper()
		form := url.Values{}
		form.Set("grant_type", "password")
		form.Set("username", "ada")
		form.Set("password", password)
		form.Set("client_id", client.ClientID)
		form.Set("client_secret", client.ClientSecret)
		resp, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, body
	}

	okResp, okBody := token("correct horse")
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("password grant status %d: %s", okResp.StatusCode, okBody)
	}
	var granted map[string]interface{}
	if err := json.Unmarshal(okBody, &granted); err != nil {
		t.Fatal(err)
	}
	if granted["access_token"] == nil || granted["access_token"] == "" {
		t.Fatalf("missing access_token: %s", okBody)
	}

	badResp, badBody := token("wrong password")
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong password status %d: %s", badResp.StatusCode, badBody)
	}
	var denied map[string]string
	if err := json.Unmarshal(badBody, &denied); err != nil {
		t.Fatal(err)
	}
	if denied["error"] != "invalid_grant" {
		t.Fatalf("error = %q", denied["error"])
	}
}
