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

	"github.com/bravo68web/atrium/pkg/crypto"
)

func TestOutOfBandAuthorizationCode(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)

	regBody := `{"client_name":"CLI","redirect_uris":["urn:ietf:wg:oauth:2.0:oob"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"none"}`
	reg, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	var client struct {
		ID string `json:"client_id"`
	}
	rawReg, _ := io.ReadAll(reg.Body)
	_ = reg.Body.Close()
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("register %d %s", reg.StatusCode, rawReg)
	}
	if err := json.Unmarshal(rawReg, &client); err != nil {
		t.Fatal(err)
	}

	verifier, err := crypto.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge := crypto.GenerateCodeChallenge(verifier)
	noPKCE := authorizeQuery(client.ID, "urn:ietf:wg:oauth:2.0:oob", "", "")
	missing, err := http.Get(ts.URL + "/oauth/authorize?" + noPKCE)
	if err != nil {
		t.Fatal(err)
	}
	missingBody, _ := io.ReadAll(missing.Body)
	_ = missing.Body.Close()
	if missing.StatusCode != http.StatusBadRequest || !strings.Contains(string(missingBody), "S256") {
		t.Fatalf("missing pkce %d %s", missing.StatusCode, missingBody)
	}

	plain := authorizeQuery(client.ID, "urn:ietf:wg:oauth:2.0:oob", challenge, "plain")
	plainResp, err := http.Get(ts.URL + "/oauth/authorize?" + plain)
	if err != nil {
		t.Fatal(err)
	}
	plainBody, _ := io.ReadAll(plainResp.Body)
	_ = plainResp.Body.Close()
	if plainResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(plainBody), "S256") {
		t.Fatalf("plain pkce %d %s", plainResp.StatusCode, plainBody)
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

	query := authorizeQuery(client.ID, "urn:ietf:wg:oauth:2.0:oob", challenge, "S256")
	page := followConsent(t, browser, ts, "/oauth/authorize?"+query, "approve")
	if page.StatusCode != http.StatusOK {
		t.Fatalf("code page %d %s", page.StatusCode, page.Body)
	}
	if page.Location != "" {
		t.Fatalf("location %s", page.Location)
	}
	if !strings.Contains(page.Body, `id="authorization-code"`) || !strings.Contains(page.Body, "xyz") {
		t.Fatalf("page %s", page.Body)
	}
	code := inputValue(t, page.Body, "authorization-code")
	if code == "" || strings.Contains(page.Body, "access_denied") {
		t.Fatalf("code %q page %s", code, page.Body)
	}

	wrong := tokenFromCode(t, ts.URL, client.ID, code, verifier, "https://example.com/callback")
	if wrong.Status != http.StatusBadRequest {
		t.Fatalf("wrong redirect %d %s", wrong.Status, wrong.Body)
	}
	issued := tokenFromCode(t, ts.URL, client.ID, code, verifier, "urn:ietf:wg:oauth:2.0:oob")
	if issued.Status != http.StatusOK || issued.Access == "" {
		t.Fatalf("token %d %s", issued.Status, issued.Body)
	}
	replay := tokenFromCode(t, ts.URL, client.ID, code, verifier, "urn:ietf:wg:oauth:2.0:oob")
	if replay.Status == http.StatusOK {
		t.Fatalf("replay succeeded %s", replay.Body)
	}

	denied := followConsent(t, browser, ts, "/oauth/authorize?"+authorizeQuery(client.ID, "urn:ietf:wg:oauth:2.0:oob", challenge, "S256")+"&prompt=consent", "deny")
	if denied.StatusCode != http.StatusOK || !strings.Contains(denied.Body, "access_denied") || strings.Contains(denied.Body, `id="authorization-code"`) {
		t.Fatalf("deny %d %s", denied.StatusCode, denied.Body)
	}

	other, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"Web","redirect_uris":["https://example.com/cb"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"none"}`))
	if err != nil {
		t.Fatal(err)
	}
	var web struct {
		ID string `json:"client_id"`
	}
	if err := json.NewDecoder(other.Body).Decode(&web); err != nil {
		t.Fatal(err)
	}
	_ = other.Body.Close()
	bad, err := browser.Get(ts.URL + "/oauth/authorize?" + authorizeQuery(web.ID, "urn:ietf:wg:oauth:2.0:oob", challenge, "S256"))
	if err != nil {
		t.Fatal(err)
	}
	badBody, _ := io.ReadAll(bad.Body)
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest || !strings.Contains(string(badBody), "redirect_uri") {
		t.Fatalf("unregistered %d %s", bad.StatusCode, badBody)
	}
}

type htmlPage struct {
	StatusCode   int
	Location     string
	Body         string
	CacheControl string
}

type tokenResult struct {
	Status int
	Body   string
	Access string
}

func authorizeQuery(clientID, redirectURI, challenge, method string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid")
	q.Set("state", "xyz")
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", method)
	}
	return q.Encode()
}

func followConsent(t *testing.T, browser *http.Client, ts *httptest.Server, path, action string) htmlPage {
	t.Helper()
	resp, err := browser.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/consent") {
		t.Fatalf("authorize %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	consentURL := resp.Header.Get("Location")
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
	form.Set("action", action)
	form.Set("client_id", urlValue(path, "client_id"))
	redirectURI := urlValue(path, "redirect_uri")
	if redirectURI == "" {
		redirectURI = "urn:ietf:wg:oauth:2.0:oob"
	}
	form.Set("redirect_uri", redirectURI)
	form.Set("response_type", "code")
	form.Set("scope", "openid")
	form.Set("state", "xyz")
	form.Set("code_challenge", urlValue(path, "code_challenge"))
	form.Set("code_challenge_method", "S256")
	if action == "deny" {
		form.Set("prompt", "consent")
	}
	posted, err := browser.PostForm(ts.URL+"/consent", form)
	if err != nil {
		t.Fatal(err)
	}
	postedBody, _ := io.ReadAll(posted.Body)
	_ = posted.Body.Close()
	if action == "deny" {
		return htmlPage{StatusCode: posted.StatusCode, Location: posted.Header.Get("Location"), Body: string(postedBody), CacheControl: posted.Header.Get("Cache-Control")}
	}
	if posted.StatusCode != http.StatusFound {
		t.Fatalf("consent %d %s", posted.StatusCode, postedBody)
	}
	next := posted.Header.Get("Location")
	if strings.HasPrefix(next, "/") {
		next = ts.URL + next
	}
	final, err := browser.Get(next)
	if err != nil {
		t.Fatal(err)
	}
	finalBody, _ := io.ReadAll(final.Body)
	_ = final.Body.Close()
	return htmlPage{StatusCode: final.StatusCode, Location: final.Header.Get("Location"), Body: string(finalBody), CacheControl: final.Header.Get("Cache-Control")}
}

func urlValue(raw, key string) string {
	q, err := url.ParseQuery(strings.TrimPrefix(raw, "/oauth/authorize?"))
	if err != nil {
		return ""
	}
	return q.Get(key)
}

func inputValue(t *testing.T, body, id string) string {
	t.Helper()
	key := `id="` + id + `" readonly value="`
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("input %s missing: %s", id, body)
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatal("input truncated")
	}
	return rest[:j]
}

func tokenFromCode(t *testing.T, base, clientID, code, verifier, redirectURI string) tokenResult {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)
	resp, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var parsed map[string]any
	_ = json.Unmarshal(body, &parsed)
	access, _ := parsed["access_token"].(string)
	return tokenResult{Status: resp.StatusCode, Body: string(body), Access: access}
}
