package integration

import (
	"bytes"
	"encoding/base64"
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
)

func TestXAAStaysOff(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()

	discovery := getJSONMap(t, ts.URL+"/.well-known/openid-configuration")
	if _, ok := discovery["authorization_grant_profiles_supported"]; ok {
		t.Fatalf("profile published: %v", discovery["authorization_grant_profiles_supported"])
	}
	if grantListed(discovery["grant_types_supported"], config.XAAJWTBearerGrant) {
		t.Fatal("jwt-bearer is listed while xaa is off")
	}

	status, body := postForm(t, ts.URL+"/oauth/token", "", "", url.Values{
		"grant_type":    {config.XAAJWTBearerGrant},
		"assertion":     {"not-a-token"},
		"client_id":     {"missing"},
		"client_secret": {"missing"},
	})
	if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("jwt-bearer %d %v", status, body)
	}

	status, body = postForm(t, ts.URL+"/oauth/token", "test-mgmt", "test-mgmt-secret", url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {config.XAAIDJAGTokenType},
		"subject_token":        {"header.payload.sig"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:id_token"},
	})
	if status == http.StatusOK || strings.Contains(stringMust(body["access_token"]), "eyJ") {
		t.Fatalf("id-jag issued while off: %d %v", status, body)
	}
}

func TestXAAIssuesAndRedeemsAnIDJAG(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.XAA.Enabled = true
	cfg.XAA.Trusts = []config.XAATrust{{
		ClientID:         "field-notes",
		ResourceClientID: "notes-api",
		Scopes:           []string{"notes.read"},
	}}
	cfg.XAA.IDPs = []config.XAAIdentityProvider{{
		Scopes: []string{"notes.read"},
	}}
	ts := startXAA(t, cfg)
	token := managementToken(t, ts.URL)

	app := createAPIClient(t, ts.URL, token, map[string]any{
		"id":   "field-notes",
		"name": "Field Notes",
		"grant_types": []string{
			"password",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			config.XAAJWTBearerGrant,
		},
		"scopes": []string{"openid", "email", "notes.read"},
	})
	api := createAPIClient(t, ts.URL, token, map[string]any{
		"id":          "notes-api",
		"name":        "Notes API",
		"grant_types": []string{config.XAAJWTBearerGrant},
		"scopes":      []string{"notes.read"},
	})
	ada := createAPIUser(t, ts.URL, token, "ada", "ada@fieldnotes.example", true)
	bea := createAPIUser(t, ts.URL, token, "bea", "bea@fieldnotes.example", false)

	discovery := getJSONMap(t, ts.URL+"/.well-known/openid-configuration")
	if !grantListed(discovery["grant_types_supported"], config.XAAJWTBearerGrant) {
		t.Fatalf("grants %v", discovery["grant_types_supported"])
	}
	profiles, _ := discovery["authorization_grant_profiles_supported"].([]any)
	if len(profiles) != 1 || profiles[0] != config.XAAIDJAGProfile {
		t.Fatalf("profiles %v", discovery["authorization_grant_profiles_supported"])
	}
	metadata := getJSONMap(t, ts.URL+"/.well-known/oauth-authorization-server")
	if metadata["authorization_grant_profiles_supported"] == nil {
		t.Fatal("metadata omitted the profile")
	}

	idToken := passwordIDToken(t, ts.URL, app, ada)
	if status, body := exchangeIDJAG(t, ts.URL, app, idToken, "https://other.example", "notes.read"); status != 400 || body["error"] != "invalid_target" {
		t.Fatalf("audience %d %v", status, body)
	}
	if status, body := exchangeIDJAG(t, ts.URL, app, idToken, ts.URL, "admin"); status != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("scope %d %v", status, body)
	}

	status, issued := exchangeIDJAG(t, ts.URL, app, idToken, ts.URL, "notes.read")
	if status != 200 {
		t.Fatalf("exchange %d %v", status, issued)
	}
	jag, _ := issued["access_token"].(string)
	if issued["issued_token_type"] != config.XAAIDJAGTokenType || issued["token_type"] != "N_A" || issued["expires_in"] != float64(300) {
		t.Fatalf("response %v", issued)
	}
	if _, ok := issued["refresh_token"]; ok {
		t.Fatal("id-jag returned a refresh token")
	}
	header := jwtJSON(t, jag, 0)
	payload := jwtJSON(t, jag, 1)
	if header["typ"] != config.XAAIDJAGTyp || header["alg"] != "RS256" {
		t.Fatalf("header %v", header)
	}
	if payload["aud"] != ts.URL || payload["iss"] != ts.URL || payload["client_id"] != "notes-api" {
		t.Fatalf("payload %v", payload)
	}
	if payload["sub"] != ada["id"] || payload["email"] != "ada@fieldnotes.example" || payload["scope"] != "notes.read" {
		t.Fatalf("subject %v user %v", payload, ada["id"])
	}
	if status, body := exchangeIDJAG(t, ts.URL, app, idToken, ts.URL, "notes.read"); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("second exchange %d %v", status, body)
	}

	tampered := tamperToken(jag)
	if status, body := redeemIDJAG(t, ts.URL, api, tampered); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("tamper %d %v", status, body)
	}
	if status, body := redeemIDJAG(t, ts.URL, app, jag); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong client %d %v", status, body)
	}
	status, access := redeemIDJAG(t, ts.URL, api, jag)
	if status != 200 {
		t.Fatalf("redeem %d %v", status, access)
	}
	accessToken, _ := access["access_token"].(string)
	if access["token_type"] != "Bearer" || strings.Contains(accessToken, ".") {
		t.Fatalf("access %v", access)
	}
	if _, ok := access["refresh_token"]; ok {
		t.Fatal("redeem returned a refresh token")
	}
	intro := introspectAs(t, ts.URL, api, accessToken)
	if intro["active"] != true || intro["sub"] != ada["id"] || intro["scope"] != "notes.read" {
		t.Fatalf("introspect %v", intro)
	}
	if status, body := redeemIDJAG(t, ts.URL, api, jag); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replay %d %v", status, body)
	}

	beaToken := passwordIDToken(t, ts.URL, app, bea)
	status, beaJAG := exchangeIDJAG(t, ts.URL, app, beaToken, ts.URL, "")
	if status != 200 {
		t.Fatalf("bea exchange %d %v", status, beaJAG)
	}
	if status, body := redeemIDJAG(t, ts.URL, api, beaJAG["access_token"].(string)); status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("unverified %d %v", status, body)
	}

	password := passwordGrant(t, ts.URL, app, ada)
	status, swapped := postForm(t, ts.URL+"/oauth/token", app["id"].(string), app["secret"].(string), url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {password["access_token"].(string)},
	})
	if status != 200 || swapped["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("local exchange %d %v", status, swapped)
	}
}

func startXAA(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()
	cfg.Security.Issuer = issuer
	cfg.OIDC.Issuer = issuer
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	for i := range cfg.XAA.Trusts {
		if cfg.XAA.Trusts[i].Audience == "" {
			cfg.XAA.Trusts[i].Audience = issuer
		}
	}
	for i := range cfg.XAA.IDPs {
		if cfg.XAA.IDPs[i].Issuer == "" {
			cfg.XAA.IDPs[i].Issuer = issuer
			cfg.XAA.IDPs[i].JWKSURI = issuer + "/oidc/jwks"
		}
	}
	db := testpg.Open(t)
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(8))
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
	t.Cleanup(ts.Close)
	if ts.URL != issuer {
		t.Fatalf("url %s issuer %s", ts.URL, issuer)
	}
	return ts
}

func managementToken(t *testing.T, base string) string {
	t.Helper()
	status, body := postForm(t, base+"/oauth/token", "test-mgmt", "test-mgmt-secret", url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"management"},
	})
	if status != 200 {
		t.Fatalf("management %d %v", status, body)
	}
	return body["access_token"].(string)
}

func createAPIClient(t *testing.T, base, token string, payload map[string]any) map[string]any {
	t.Helper()
	status, body := postJSON(t, base+"/api/clients", token, payload)
	if status != http.StatusCreated || body["id"] == "" || body["secret"] == "" {
		t.Fatalf("client %d %v", status, body)
	}
	return body
}

func createAPIUser(t *testing.T, base, token, username, email string, verified bool) map[string]any {
	t.Helper()
	status, body := postJSON(t, base+"/api/users", token, map[string]any{
		"username":       username,
		"password":       "correct-horse",
		"email":          email,
		"email_verified": verified,
	})
	if status != http.StatusCreated || body["id"] == "" {
		t.Fatalf("user %d %v", status, body)
	}
	body["password"] = "correct-horse"
	return body
}

func passwordIDToken(t *testing.T, base string, client, user map[string]any) string {
	t.Helper()
	body := passwordGrant(t, base, client, user)
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("missing id token %v", body)
	}
	return idToken
}

func passwordGrant(t *testing.T, base string, client, user map[string]any) map[string]any {
	t.Helper()
	status, body := postForm(t, base+"/oauth/token", client["id"].(string), client["secret"].(string), url.Values{
		"grant_type": {"password"},
		"username":   {user["username"].(string)},
		"password":   {user["password"].(string)},
		"scope":      {"openid email"},
	})
	if status != 200 {
		t.Fatalf("password %d %v", status, body)
	}
	return body
}

func exchangeIDJAG(t *testing.T, base string, client map[string]any, idToken, audience, scope string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {config.XAAIDJAGTokenType},
		"subject_token":        {idToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:id_token"},
		"audience":             {audience},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return postForm(t, base+"/oauth/token", client["id"].(string), client["secret"].(string), form)
}

func redeemIDJAG(t *testing.T, base string, client map[string]any, assertion string) (int, map[string]any) {
	t.Helper()
	return postForm(t, base+"/oauth/token", client["id"].(string), client["secret"].(string), url.Values{
		"grant_type": {config.XAAJWTBearerGrant},
		"assertion":  {assertion},
	})
}

func introspectAs(t *testing.T, base string, client map[string]any, token string) map[string]any {
	t.Helper()
	status, body := postForm(t, base+"/oauth/introspect", client["id"].(string), client["secret"].(string), url.Values{
		"token": {token},
	})
	if status != 200 {
		t.Fatalf("introspect %d %v", status, body)
	}
	return body
}

func postForm(t *testing.T, rawURL, id, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		req.SetBasicAuth(id, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return decodeBody(t, resp)
}

func postJSON(t *testing.T, rawURL, token string, payload any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return decodeBody(t, resp)
}

func getJSONMap(t *testing.T, rawURL string) map[string]any {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	status, body := decodeBody(t, resp)
	if status != 200 {
		t.Fatalf("%s %d %v", rawURL, status, body)
	}
	return body
}

func decodeBody(t *testing.T, resp *http.Response) (int, map[string]any) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("status %d body %s", resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, body
}

func jwtJSON(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < index+1 {
		t.Fatalf("jwt %s", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func tamperToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token + "x"
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(raw) == 0 {
		parts[2] = "AAAA"
		return strings.Join(parts, ".")
	}
	// The last base64 character can change without changing the decoded
	// signature when that character only carries padding bits.
	raw[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

func grantListed(value any, grant string) bool {
	list, _ := value.([]any)
	for _, item := range list {
		if item == grant {
			return true
		}
	}
	return false
}

func stringMust(value any) string {
	text, _ := value.(string)
	return text
}
