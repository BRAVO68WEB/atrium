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

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	root "github.com/bravo68web/atrium"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/queue"
	"github.com/bravo68web/atrium/internal/server"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/testpg"
)

func TestLoginCSRF(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	resp, err := http.PostForm(ts.URL+"/login", url.Values{"username": {"ada"}, "password": {"correct horse"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "csrf_failed") {
		t.Fatalf("missing csrf = %d %s", resp.StatusCode, body)
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	form := url.Values{"username": {"ada"}, "password": {"not-the-password"}}
	form.Set("csrf_token", csrfToken(t, browser, ts.URL+"/login"))
	page, err := browser.PostForm(ts.URL+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode == http.StatusForbidden || strings.Contains(string(pageBody), "csrf_failed") {
		t.Fatalf("csrf rejected a matching token: %d %s", page.StatusCode, pageBody)
	}
	if !strings.Contains(string(pageBody), "Invalid credentials") {
		t.Fatalf("expected the password check, got %s", pageBody)
	}
}

func TestAuditListHidesSecrets(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	body := `{"name":"Audited","redirect_uris":["https://example.com/cb"],"grant_types":["client_credentials"],"scopes":["openid"]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/clients", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	created, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(created.Body)
	_ = created.Body.Close()
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create %d %s", created.StatusCode, raw)
	}
	var client map[string]any
	_ = json.Unmarshal(raw, &client)
	secret, _ := client["secret"].(string)
	if secret == "" {
		t.Fatal("expected a client secret")
	}

	listReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/audit?window=1h&action=client.create", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listed, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	auditBody, _ := io.ReadAll(listed.Body)
	_ = listed.Body.Close()
	if listed.StatusCode != http.StatusOK {
		t.Fatalf("audit %d %s", listed.StatusCode, auditBody)
	}
	if !strings.Contains(string(auditBody), "client.create") || strings.Contains(string(auditBody), secret) {
		t.Fatalf("audit row leaked or missing: %s", auditBody)
	}

	userToken := userAccessToken(t, ts)
	userReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/audit", nil)
	userReq.Header.Set("Authorization", "Bearer "+userToken)
	denied, err := http.DefaultClient.Do(userReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("user audit status %d", denied.StatusCode)
	}
}

func TestDCRDisabled(t *testing.T) {
	ts, cleanup := setupPlatformServer(t, func(cfg *config.Config) {
		cfg.Registration.DCREnabled = false
	})
	defer cleanup()
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"Nope","redirect_uris":["https://example.com/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "registration_disabled") {
		t.Fatalf("register %d %s", resp.StatusCode, body)
	}
}

func TestCIMDFetchOnceThenDisabled(t *testing.T) {
	var hits int
	var meta *httptest.Server
	meta = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":     meta.URL,
			"client_name":   "Metadata App",
			"redirect_uris": []string{"https://app.example/cb"},
			"grant_types":   []string{"authorization_code"},
		})
	}))
	defer meta.Close()
	var db *database.DB
	ts, cleanup := setupPlatformServer(t, func(cfg *config.Config) {
		cfg.Registration.CIMDEnabled = true
		cfg.Security.AllowInsecureFetch = true
		cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	})
	defer cleanup()
	db = platformDB
	clientID := meta.URL
	authorize := ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape("https://app.example/cb") + "&response_type=code&scope=openid"
	for i := 0; i < 2; i++ {
		resp, err := http.Get(authorize)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(raw), "invalid_client") {
			t.Fatalf("authorize %d %s", resp.StatusCode, raw)
		}
	}
	if hits != 1 {
		t.Fatalf("metadata fetches = %d", hits)
	}
	if _, err := db.Exec(`UPDATE clients SET cimd_enabled = 0 WHERE id = ?`, clientID); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(authorize)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_client") {
		t.Fatalf("disabled cimd %d %s", resp.StatusCode, raw)
	}
	if hits != 1 {
		t.Fatalf("disabled row fetched again: %d", hits)
	}
}

func TestForcedDPoP(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	mgmt := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, mgmt)
	body := `{"name":"Bound","redirect_uris":["https://example.com/cb"],"grant_types":["password"],"scopes":["openid","profile"],"dpop_bound_access_tokens":true}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/clients", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+mgmt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&client)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || client.Secret == "" {
		t.Fatalf("client status %d %+v", resp.StatusCode, client)
	}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "ada")
	form.Set("password", "correct horse")
	form.Set("scope", "openid profile")
	plain, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(form.Encode()))
	plain.SetBasicAuth(client.ID, client.Secret)
	plain.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denied, err := http.DefaultClient.Do(plain)
	if err != nil {
		t.Fatal(err)
	}
	deniedBody, _ := io.ReadAll(denied.Body)
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusBadRequest || !strings.Contains(string(deniedBody), "invalid_dpop_proof") {
		t.Fatalf("token without proof %d %s", denied.StatusCode, deniedBody)
	}

	dpop := service.NewDPoPService()
	key, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.CreateDPoPProof(key, http.MethodPost, ts.URL+"/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	with, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(form.Encode()))
	with.SetBasicAuth(client.ID, client.Secret)
	with.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	with.Header.Set("DPoP", proof)
	ok, err := http.DefaultClient.Do(with)
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	_ = json.NewDecoder(ok.Body).Decode(&token)
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK || token["token_type"] != "DPoP" {
		t.Fatalf("dpop token %d %+v", ok.StatusCode, token)
	}
	access, _ := token["access_token"].(string)

	info, _ := http.NewRequest(http.MethodGet, ts.URL+"/oidc/userinfo", nil)
	info.Header.Set("Authorization", "Bearer "+access)
	bearer, err := http.DefaultClient.Do(info)
	if err != nil {
		t.Fatal(err)
	}
	_ = bearer.Body.Close()
	if bearer.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer userinfo %d", bearer.StatusCode)
	}

	infoProof, err := dpop.CreateDPoPProof(key, http.MethodGet, ts.URL+"/oidc/userinfo", access)
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := http.NewRequest(http.MethodGet, ts.URL+"/oidc/userinfo", nil)
	bound.Header.Set("Authorization", "DPoP "+access)
	bound.Header.Set("DPoP", infoProof)
	userinfo, err := http.DefaultClient.Do(bound)
	if err != nil {
		t.Fatal(err)
	}
	infoBody, _ := io.ReadAll(userinfo.Body)
	_ = userinfo.Body.Close()
	if userinfo.StatusCode != http.StatusOK || !strings.Contains(string(infoBody), "ada") {
		t.Fatalf("dpop userinfo %d %s", userinfo.StatusCode, infoBody)
	}

	other, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	stolen, err := dpop.CreateDPoPProof(other, http.MethodGet, ts.URL+"/oidc/userinfo", access)
	if err != nil {
		t.Fatal(err)
	}
	wrong, _ := http.NewRequest(http.MethodGet, ts.URL+"/oidc/userinfo", nil)
	wrong.Header.Set("Authorization", "DPoP "+access)
	wrong.Header.Set("DPoP", stolen)
	rejected, err := http.DefaultClient.Do(wrong)
	if err != nil {
		t.Fatal(err)
	}
	rejectedBody, _ := io.ReadAll(rejected.Body)
	_ = rejected.Body.Close()
	if rejected.StatusCode != http.StatusUnauthorized || !strings.Contains(string(rejectedBody), "does not match") {
		t.Fatalf("wrong dpop key %d %s", rejected.StatusCode, rejectedBody)
	}

	meURL := ts.URL + "/api/me"
	meProof, err := dpop.CreateDPoPProof(key, http.MethodGet, meURL, access)
	if err != nil {
		t.Fatal(err)
	}
	me, _ := http.NewRequest(http.MethodGet, meURL, nil)
	me.Header.Set("Authorization", "DPoP "+access)
	me.Header.Set("DPoP", meProof)
	meResp, err := http.DefaultClient.Do(me)
	if err != nil {
		t.Fatal(err)
	}
	meBody, _ := io.ReadAll(meResp.Body)
	_ = meResp.Body.Close()
	if meResp.StatusCode != http.StatusOK || !strings.Contains(string(meBody), "ada") {
		t.Fatalf("dpop profile %d %s", meResp.StatusCode, meBody)
	}
	meWrong, err := dpop.CreateDPoPProof(other, http.MethodGet, meURL, access)
	if err != nil {
		t.Fatal(err)
	}
	meBad, _ := http.NewRequest(http.MethodGet, meURL, nil)
	meBad.Header.Set("Authorization", "DPoP "+access)
	meBad.Header.Set("DPoP", meWrong)
	meBadResp, err := http.DefaultClient.Do(meBad)
	if err != nil {
		t.Fatal(err)
	}
	meBadBody, _ := io.ReadAll(meBadResp.Body)
	_ = meBadResp.Body.Close()
	if meBadResp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(meBadBody), "does not match") {
		t.Fatalf("profile wrong key %d %s", meBadResp.StatusCode, meBadBody)
	}

	refreshToken, _ := token["refresh_token"].(string)
	tokenURL := ts.URL + "/oauth/token"
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refreshToken)
	badRefreshProof, err := dpop.CreateDPoPProof(other, http.MethodPost, tokenURL, "")
	if err != nil {
		t.Fatal(err)
	}
	badRefresh, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(refreshForm.Encode()))
	badRefresh.SetBasicAuth(client.ID, client.Secret)
	badRefresh.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRefresh.Header.Set("DPoP", badRefreshProof)
	badRefreshResp, err := http.DefaultClient.Do(badRefresh)
	if err != nil {
		t.Fatal(err)
	}
	badRefreshBody, _ := io.ReadAll(badRefreshResp.Body)
	_ = badRefreshResp.Body.Close()
	if badRefreshResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(badRefreshBody), "does not match") {
		t.Fatalf("refresh wrong key %d %s", badRefreshResp.StatusCode, badRefreshBody)
	}

	goodRefreshProof, err := dpop.CreateDPoPProof(key, http.MethodPost, tokenURL, "")
	if err != nil {
		t.Fatal(err)
	}
	goodRefresh, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(refreshForm.Encode()))
	goodRefresh.SetBasicAuth(client.ID, client.Secret)
	goodRefresh.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	goodRefresh.Header.Set("DPoP", goodRefreshProof)
	goodRefreshResp, err := http.DefaultClient.Do(goodRefresh)
	if err != nil {
		t.Fatal(err)
	}
	var refreshed map[string]any
	_ = json.NewDecoder(goodRefreshResp.Body).Decode(&refreshed)
	_ = goodRefreshResp.Body.Close()
	if goodRefreshResp.StatusCode != http.StatusOK {
		t.Fatalf("refresh %d %+v", goodRefreshResp.StatusCode, refreshed)
	}
	newAccess, _ := refreshed["access_token"].(string)
	revokeForm := url.Values{}
	revokeForm.Set("token", newAccess)
	badRevokeProof, err := dpop.CreateDPoPProof(other, http.MethodPost, ts.URL+"/oauth/revoke", newAccess)
	if err != nil {
		t.Fatal(err)
	}
	badRevoke, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/revoke", strings.NewReader(revokeForm.Encode()))
	badRevoke.SetBasicAuth(client.ID, client.Secret)
	badRevoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRevoke.Header.Set("DPoP", badRevokeProof)
	badRevokeResp, err := http.DefaultClient.Do(badRevoke)
	if err != nil {
		t.Fatal(err)
	}
	badRevokeBody, _ := io.ReadAll(badRevokeResp.Body)
	_ = badRevokeResp.Body.Close()
	if badRevokeResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(badRevokeBody), "does not match") {
		t.Fatalf("revoke wrong key %d %s", badRevokeResp.StatusCode, badRevokeBody)
	}
}

func TestOpenAPICoversRouter(t *testing.T) {
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(10))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(root.OpenAPISpec, &spec); err != nil {
		t.Fatal(err)
	}
	var missing []string
	_ = chi.Walk(srv.GetRouter(), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !coveredPrefix(route) {
			return nil
		}
		path := strings.TrimRight(route, "/")
		if path == "" {
			path = "/"
		}
		if _, ok := spec.Paths[path]; !ok {
			missing = append(missing, method+" "+path)
		}
		return nil
	})
	if len(missing) > 0 {
		t.Fatalf("openapi spec is missing routes:\n%s", strings.Join(missing, "\n"))
	}
}

func coveredPrefix(route string) bool {
	return strings.HasPrefix(route, "/api") || strings.HasPrefix(route, "/oauth") || strings.HasPrefix(route, "/oidc") || strings.HasPrefix(route, "/.well-known")
}

var platformDB *database.DB

func setupPlatformServer(t *testing.T, tweak func(*config.Config)) (*httptest.Server, func()) {
	t.Helper()
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	cfg.Security.RequirePKCE = false
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	if tweak != nil {
		tweak(cfg)
	}
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(10))
	if err != nil {
		t.Fatal(err)
	}
	platformDB = db
	ts := httptest.NewServer(srv.GetRouter())
	return ts, func() {
		ts.Close()
		_ = db.Close()
	}
}

func userAccessToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	mgmt := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, mgmt)
	reg, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"User","redirect_uris":["https://example.com/cb"],"grant_types":["password"],"scope":"openid"}`))
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ID     string `json:"client_id"`
		Secret string `json:"client_secret"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&client)
	_ = reg.Body.Close()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "ada")
	form.Set("password", "correct horse")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(form.Encode()))
	req.SetBasicAuth(client.ID, client.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&token)
	_ = resp.Body.Close()
	access, _ := token["access_token"].(string)
	if resp.StatusCode != http.StatusOK || access == "" {
		t.Fatalf("user token %d %+v", resp.StatusCode, token)
	}
	return access
}
