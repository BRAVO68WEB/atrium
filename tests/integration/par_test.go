package integration

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func TestPARAuthorizeAndMissingRedirect(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	mgmt := managementToken(t, ts.URL)
	createAPIUser(t, ts.URL, mgmt, "ada", "ada@example.com", true)
	client := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":                       "Notes",
		"redirect_uris":              []string{"https://app.example/cb"},
		"grant_types":                []string{"authorization_code"},
		"scopes":                     []string{"openid", "profile"},
		"token_endpoint_auth_method": "client_secret_basic",
	})

	pushed, pushBody := postForm(t, ts.URL+"/oauth/par", client["id"].(string), client["secret"].(string), url.Values{
		"response_type": {"code"},
		"redirect_uri":  {"https://app.example/cb"},
		"scope":         {"openid profile"},
		"state":         {"par-state"},
	})
	if pushed != http.StatusCreated {
		t.Fatalf("par %d %v", pushed, pushBody)
	}
	requestURI, _ := pushBody["request_uri"].(string)
	if requestURI == "" || pushBody["expires_in"] == nil {
		t.Fatalf("par %v", pushBody)
	}
	code := authorizePAR(t, ts.URL, client["id"].(string), requestURI)
	if code == "" {
		t.Fatal("missing code")
	}

	many := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":                       "Two",
		"redirect_uris":              []string{"https://one.example/cb", "https://two.example/cb"},
		"grant_types":                []string{"authorization_code"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	missing, missingBody := postForm(t, ts.URL+"/oauth/par", many["id"].(string), many["secret"].(string), url.Values{
		"response_type": {"code"},
		"scope":         {"openid"},
	})
	if missing != http.StatusBadRequest || missingBody["error"] != "invalid_request" {
		t.Fatalf("missing redirect %d %v", missing, missingBody)
	}
}

func authorizePAR(t *testing.T, base, clientID, requestURI string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct-horse")
	login.Set("csrf_token", csrfToken(t, browser, base+"/login"))
	loginResp, err := browser.PostForm(base+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()

	query := url.Values{}
	query.Set("client_id", clientID)
	query.Set("request_uri", requestURI)
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
	if !strings.Contains(string(pageBody), "openid") {
		t.Fatalf("consent %s", pageBody)
	}
	form := url.Values{}
	form.Set("csrf_token", csrfFromBody(t, string(pageBody)))
	form.Set("action", "approve")
	form.Set("client_id", clientID)
	form.Set("request_uri", requestURI)
	approved, err := browser.PostForm(base+"/consent", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = approved.Body.Close()
	next := approved.Header.Get("Location")
	if strings.HasPrefix(next, "/") {
		next = base + next
	}
	issued, err := browser.Get(next)
	if err != nil {
		t.Fatal(err)
	}
	_ = issued.Body.Close()
	loc := issued.Header.Get("Location")
	if issued.StatusCode != http.StatusFound {
		t.Fatalf("code %d %s", issued.StatusCode, loc)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("code")
}
