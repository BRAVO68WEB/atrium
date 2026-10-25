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
	"github.com/bravo68web/atrium/internal/queue"
	"github.com/bravo68web/atrium/internal/server"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func TestActorTokenMustMatchAndRefreshKeepsIt(t *testing.T) {
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	cfg.Security.RequirePKCE = false
	cfg.Security.AccessTokenFormat = "jwt"
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(100))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.GetRouter())
	defer ts.Close()
	createUser(t, ts.URL, managementAccessToken(t, ts.URL))

	app := registerClient(t, ts.URL, `{"client_name":"Assistant","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code","refresh_token"],"scope":"openid","token_endpoint_auth_method":"none"}`)
	actor := registerClient(t, ts.URL, `{"client_name":"Finance Agent","redirect_uris":["https://agent.example/cb"],"grant_types":["client_credentials"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	other := registerClient(t, ts.URL, `{"client_name":"Other Agent","redirect_uris":["https://other.example/cb"],"grant_types":["client_credentials"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	actorToken := clientCredentialsToken(t, ts.URL, actor.ID, actor.Secret)
	otherToken := clientCredentialsToken(t, ts.URL, other.ID, other.Secret)

	verifier, err := crypto.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge := crypto.GenerateCodeChallenge(verifier)

	badType, _ := url.ParseQuery(actorAuthorizeQuery(app.ID, actor.ID, challenge, "S256"))
	badType.Set("response_type", "token")
	rejected, err := http.Get(ts.URL + "/oauth/authorize?" + badType.Encode())
	if err != nil {
		t.Fatal(err)
	}
	rejectedBody, _ := io.ReadAll(rejected.Body)
	_ = rejected.Body.Close()
	if rejected.StatusCode != http.StatusBadRequest || !strings.Contains(string(rejectedBody), "response_type code") {
		t.Fatalf("response type %d %s", rejected.StatusCode, rejectedBody)
	}
	plainResp, err := http.Get(ts.URL + "/oauth/authorize?" + actorAuthorizeQuery(app.ID, actor.ID, challenge, "plain"))
	if err != nil {
		t.Fatal(err)
	}
	plainBody, _ := io.ReadAll(plainResp.Body)
	_ = plainResp.Body.Close()
	if plainResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(plainBody), "S256") {
		t.Fatalf("plain pkce %d %s", plainResp.StatusCode, plainBody)
	}

	browser := signInAda(t, ts.URL)
	none, _ := url.ParseQuery(actorAuthorizeQuery(app.ID, actor.ID, challenge, "S256"))
	none.Set("prompt", "none")
	silent, err := browser.Get(ts.URL + "/oauth/authorize?" + none.Encode())
	if err != nil {
		t.Fatal(err)
	}
	silentBody, _ := io.ReadAll(silent.Body)
	_ = silent.Body.Close()
	if silent.StatusCode != http.StatusFound || !strings.Contains(string(silentBody), "consent_required") {
		t.Fatalf("prompt none %d %s", silent.StatusCode, silentBody)
	}

	userQuery := url.Values{}
	userQuery.Set("client_id", app.ID)
	userQuery.Set("response_type", "code")
	userQuery.Set("redirect_uri", "https://app.example/cb")
	userQuery.Set("scope", "openid")
	userQuery.Set("state", "xyz")
	userQuery.Set("code_challenge", challenge)
	userQuery.Set("code_challenge_method", "S256")
	userCode := codeFromConsent(t, browser, ts.URL, userQuery)
	userAccess := exchangeCode(t, ts.URL, app.ID, userCode, verifier, "")
	if userAccess.Status != http.StatusOK || strings.Count(userAccess.Access, ".") != 2 {
		t.Fatalf("user token %d %s", userAccess.Status, userAccess.Body)
	}

	resource := "https://api.example/finance"
	actorQuery, _ := url.ParseQuery(actorAuthorizeQuery(app.ID, actor.ID, challenge, "S256"))
	actorQuery.Set("resource", resource)
	code := codeFromConsent(t, browser, ts.URL, actorQuery)

	for _, token := range []string{userAccess.Access, otherToken} {
		got := exchangeCode(t, ts.URL, app.ID, code, verifier, token)
		if got.Status != http.StatusBadRequest || !strings.Contains(got.Body, "does not match") {
			t.Fatalf("wrong actor %d %s", got.Status, got.Body)
		}
	}
	revokeAccessToken(t, ts.URL, actor.ID, actor.Secret, actorToken)
	revoked := exchangeCode(t, ts.URL, app.ID, code, verifier, actorToken)
	if revoked.Status != http.StatusBadRequest || !strings.Contains(revoked.Body, "does not match") {
		t.Fatalf("revoked actor %d %s", revoked.Status, revoked.Body)
	}

	freshActor := clientCredentialsToken(t, ts.URL, actor.ID, actor.Secret)
	issued := exchangeCode(t, ts.URL, app.ID, code, verifier, freshActor)
	if issued.Status != http.StatusOK {
		t.Fatalf("token %d %s", issued.Status, issued.Body)
	}
	claims := decodeAccessClaims(t, issued.Access)
	act, _ := claims["act"].(map[string]any)
	if claims["aud"] != resource || claims["client_id"] != app.ID || act["sub"] != actor.ID {
		t.Fatalf("delegated claims %v", claims)
	}
	seen := introspectToken(t, ts.URL, "test-mgmt", "test-mgmt-secret", issued.Access)
	seenAct, _ := seen["act"].(map[string]any)
	if seen["active"] != true || seenAct["sub"] != actor.ID {
		t.Fatalf("introspect %v", seen)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(issued.Body), &parsed); err != nil {
		t.Fatal(err)
	}
	refresh, _ := parsed["refresh_token"].(string)
	rotated := refreshAccess(t, ts.URL, app.ID, refresh)
	if rotated.Status != http.StatusOK || rotated.Access == issued.Access {
		t.Fatalf("refresh %d %s", rotated.Status, rotated.Body)
	}
	next := decodeAccessClaims(t, rotated.Access)
	nextAct, _ := next["act"].(map[string]any)
	if next["aud"] != resource || nextAct["sub"] != actor.ID || next["sub"] != claims["sub"] {
		t.Fatalf("refreshed claims %v", next)
	}

	again, err := browser.Get(ts.URL + "/oauth/authorize?" + actorQuery.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = again.Body.Close()
	if again.StatusCode != http.StatusFound || !strings.Contains(again.Header.Get("Location"), "/consent") {
		t.Fatalf("second consent %d %s", again.StatusCode, again.Header.Get("Location"))
	}
}

func signInAda(t *testing.T, base string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct horse")
	login.Set("csrf_token", csrfToken(t, browser, base+"/login"))
	resp, err := browser.PostForm(base+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return browser
}

func codeFromConsent(t *testing.T, browser *http.Client, base string, query url.Values) string {
	t.Helper()
	auth, err := browser.Get(base + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = auth.Body.Close()
	if auth.StatusCode != http.StatusFound || !strings.Contains(auth.Header.Get("Location"), "/consent") {
		t.Fatalf("authorize %d %s", auth.StatusCode, auth.Header.Get("Location"))
	}
	consentURL := auth.Header.Get("Location")
	if strings.HasPrefix(consentURL, "/") {
		consentURL = base + consentURL
	}
	consent, err := browser.Get(consentURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(consent.Body)
	_ = consent.Body.Close()
	form := url.Values{}
	form.Set("csrf_token", csrfFromBody(t, string(body)))
	form.Set("action", "approve")
	for key := range query {
		form.Set(key, query.Get(key))
	}
	posted, err := browser.PostForm(base+"/consent", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = posted.Body.Close()
	if posted.StatusCode != http.StatusFound {
		t.Fatalf("approve %d", posted.StatusCode)
	}
	next := posted.Header.Get("Location")
	if strings.HasPrefix(next, "/") {
		next = base + next
	}
	issued, err := browser.Get(next)
	if err != nil {
		t.Fatal(err)
	}
	issuedBody, _ := io.ReadAll(issued.Body)
	_ = issued.Body.Close()
	if issued.StatusCode != http.StatusFound {
		t.Fatalf("code %d %s", issued.StatusCode, issuedBody)
	}
	loc, err := url.Parse(issued.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("location %s", issued.Header.Get("Location"))
	}
	return code
}

func refreshAccess(t *testing.T, base, clientID, refresh string) tokenResult {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
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

func revokeAccessToken(t *testing.T, base, id, secret, token string) {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	req, err := http.NewRequest(http.MethodPost, base+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke %d %s", resp.StatusCode, body)
	}
}

func introspectToken(t *testing.T, base, id, secret, token string) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	req, err := http.NewRequest(http.MethodPost, base+"/oauth/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("introspect %d %s", resp.StatusCode, raw)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect %d %s", resp.StatusCode, raw)
	}
	return body
}
