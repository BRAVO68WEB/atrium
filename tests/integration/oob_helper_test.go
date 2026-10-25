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

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/oobcode"
	"github.com/bravo68web/atrium/internal/queue"
	"github.com/bravo68web/atrium/internal/server"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func TestOOBHelperStaysOff(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	resp, err := http.Get(ts.URL + "/oauth/oob?code=abc&state=xyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestOOBHelperCombinedCode(t *testing.T) {
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Security.OOBHelper = true
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(100))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.GetRouter())
	defer ts.Close()

	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)
	redirectURI := ts.URL + "/oauth/oob"
	body := `{"name":"Helper","redirect_uris":["` + redirectURI + `"],"grant_types":["authorization_code"],"scopes":["openid"],"token_endpoint_auth_method":"none"}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/clients", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ID string `json:"id"`
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create client %d %s", resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, &client); err != nil {
		t.Fatal(err)
	}

	verifier, err := crypto.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct horse")
	login.Set("csrf_token", csrfToken(t, browser, ts.URL+"/login"))
	loginResp, err := browser.PostForm(ts.URL+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()

	query := url.Values{}
	query.Set("client_id", client.ID)
	query.Set("response_type", "code")
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid")
	query.Set("state", "helper-state")
	query.Set("code_challenge", crypto.GenerateCodeChallenge(verifier))
	query.Set("code_challenge_method", "S256")
	auth, err := browser.Get(ts.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	authBody, _ := io.ReadAll(auth.Body)
	_ = auth.Body.Close()
	if auth.StatusCode != http.StatusFound || !strings.Contains(auth.Header.Get("Location"), "/consent") {
		t.Fatalf("authorize %d %s %s", auth.StatusCode, auth.Header.Get("Location"), authBody)
	}
	consentURL := auth.Header.Get("Location")
	if strings.HasPrefix(consentURL, "/") {
		consentURL = ts.URL + consentURL
	}
	consent, err := browser.Get(consentURL)
	if err != nil {
		t.Fatal(err)
	}
	consentBody, _ := io.ReadAll(consent.Body)
	_ = consent.Body.Close()
	form := url.Values{}
	form.Set("csrf_token", csrfFromBody(t, string(consentBody)))
	form.Set("action", "approve")
	form.Set("client_id", client.ID)
	form.Set("redirect_uri", redirectURI)
	form.Set("response_type", "code")
	form.Set("scope", "openid")
	form.Set("state", "helper-state")
	form.Set("code_challenge", query.Get("code_challenge"))
	form.Set("code_challenge_method", "S256")
	posted, err := browser.PostForm(ts.URL+"/consent", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = posted.Body.Close()
	if posted.StatusCode != http.StatusFound {
		t.Fatalf("consent %d", posted.StatusCode)
	}
	next := posted.Header.Get("Location")
	if strings.HasPrefix(next, "/") {
		next = ts.URL + next
	}
	issued, err := browser.Get(next)
	if err != nil {
		t.Fatal(err)
	}
	issuedBody, _ := io.ReadAll(issued.Body)
	_ = issued.Body.Close()
	if issued.StatusCode != http.StatusFound || !strings.Contains(issued.Header.Get("Location"), "/oauth/oob") {
		t.Fatalf("issue %d %s %s", issued.StatusCode, issued.Header.Get("Location"), issuedBody)
	}
	helperURL := issued.Header.Get("Location")
	if strings.HasPrefix(helperURL, "/") {
		helperURL = ts.URL + helperURL
	}
	page, err := browser.Get(helperURL)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK {
		t.Fatalf("helper %d %s", page.StatusCode, pageBody)
	}
	combined := inputValue(t, string(pageBody), "combined-code")
	asCode := tokenFromCode(t, ts.URL, client.ID, combined, verifier, redirectURI)
	if asCode.Status == http.StatusOK {
		t.Fatalf("combined value was accepted as an authorization code: %s", asCode.Body)
	}
	recovered, err := oobcode.Recover(combined, "helper-state")
	if err != nil {
		t.Fatal(err)
	}
	result := tokenFromCode(t, ts.URL, client.ID, recovered, verifier, redirectURI)
	if result.Status != http.StatusOK || result.Access == "" {
		t.Fatalf("token %d %s", result.Status, result.Body)
	}
}
