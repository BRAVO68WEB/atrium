package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
)

func TestActorDelegation(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	mgmt := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, mgmt)

	app := registerClient(t, ts.URL, `{"client_name":"Assistant","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code","refresh_token"],"scope":"openid","token_endpoint_auth_method":"none"}`)
	actor := registerClient(t, ts.URL, `{"client_name":"Finance Agent","redirect_uris":["https://agent.example/cb"],"grant_types":["client_credentials"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	actorToken := clientCredentialsToken(t, ts.URL, actor.ID, actor.Secret)

	verifier, err := crypto.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge := crypto.GenerateCodeChallenge(verifier)

	missingPKCE := actorAuthorizeQuery(app.ID, actor.ID, "", "")
	missing, err := http.Get(ts.URL + "/oauth/authorize?" + missingPKCE)
	if err != nil {
		t.Fatal(err)
	}
	missingBody, _ := io.ReadAll(missing.Body)
	_ = missing.Body.Close()
	if missing.StatusCode != http.StatusBadRequest || !strings.Contains(string(missingBody), "S256") {
		t.Fatalf("missing pkce %d %s", missing.StatusCode, missingBody)
	}

	unknown := actorAuthorizeQuery(app.ID, "not-an-actor", challenge, "S256")
	unknownResp, err := http.Get(ts.URL + "/oauth/authorize?" + unknown)
	if err != nil {
		t.Fatal(err)
	}
	unknownBody, _ := io.ReadAll(unknownResp.Body)
	_ = unknownResp.Body.Close()
	if unknownResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(unknownBody), "not recognized") {
		t.Fatalf("unknown actor %d %s", unknownResp.StatusCode, unknownBody)
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

	query := actorAuthorizeQuery(app.ID, actor.ID, challenge, "S256")
	authResp, err := browser.Get(ts.URL + "/oauth/authorize?" + query)
	if err != nil {
		t.Fatal(err)
	}
	_ = authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound || !strings.Contains(authResp.Header.Get("Location"), "/consent") {
		t.Fatalf("authorize %d %s", authResp.StatusCode, authResp.Header.Get("Location"))
	}
	consentURL := authResp.Header.Get("Location")
	if strings.HasPrefix(consentURL, "/") {
		consentURL = ts.URL + consentURL
	}
	consent, err := browser.Get(consentURL)
	if err != nil {
		t.Fatal(err)
	}
	consentBody, _ := io.ReadAll(consent.Body)
	_ = consent.Body.Close()
	if !strings.Contains(string(consentBody), "Finance Agent") {
		t.Fatalf("consent page %s", consentBody)
	}
	form := url.Values{}
	form.Set("csrf_token", csrfFromBody(t, string(consentBody)))
	form.Set("action", "approve")
	form.Set("client_id", app.ID)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("response_type", "code")
	form.Set("scope", "openid")
	form.Set("state", "xyz")
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")
	form.Set("requested_actor", actor.ID)
	approved, err := browser.PostForm(ts.URL+"/consent", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = approved.Body.Close()
	if approved.StatusCode != http.StatusFound {
		t.Fatalf("approve %d", approved.StatusCode)
	}
	next := approved.Header.Get("Location")
	if strings.HasPrefix(next, "/") {
		next = ts.URL + next
	}
	issued, err := browser.Get(next)
	if err != nil {
		t.Fatal(err)
	}
	if issued.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(issued.Body)
		_ = issued.Body.Close()
		t.Fatalf("code redirect %d %s", issued.StatusCode, body)
	}
	_ = issued.Body.Close()
	loc, err := url.Parse(issued.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("location %s", issued.Header.Get("Location"))
	}

	noActor := exchangeCode(t, ts.URL, app.ID, code, verifier, "")
	if noActor.Status != http.StatusBadRequest || !strings.Contains(noActor.Body, "actor_token") {
		t.Fatalf("missing actor token %d %s", noActor.Status, noActor.Body)
	}
	wrong := exchangeCode(t, ts.URL, app.ID, code, verifier, "not-a-token")
	if wrong.Status != http.StatusBadRequest {
		t.Fatalf("wrong actor token %d %s", wrong.Status, wrong.Body)
	}
	ok := exchangeCode(t, ts.URL, app.ID, code, verifier, actorToken)
	if ok.Status != http.StatusOK || ok.Access == "" {
		t.Fatalf("token %d %s", ok.Status, ok.Body)
	}
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(ok.Access, claims)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header["typ"] != "at+jwt" {
		t.Fatalf("typ %v", parsed.Header["typ"])
	}
	if claims["azp"] != app.ID || claims["client_id"] != app.ID || claims["aud"] != "http://localhost:8080" {
		t.Fatalf("claims %v", claims)
	}
	if claims["sub"] == "" || claims["sub"] == app.ID || claims["sub"] == actor.ID {
		t.Fatalf("sub %v", claims["sub"])
	}
	act, _ := claims["act"].(map[string]any)
	if act["sub"] != actor.ID {
		t.Fatalf("act %v", claims["act"])
	}
	replay := exchangeCode(t, ts.URL, app.ID, code, verifier, actorToken)
	if replay.Status == http.StatusOK {
		t.Fatalf("replay %s", replay.Body)
	}

	plainQuery := url.Values{}
	plainQuery.Set("client_id", app.ID)
	plainQuery.Set("response_type", "code")
	plainQuery.Set("redirect_uri", "https://app.example/cb")
	plainQuery.Set("scope", "openid")
	plainQuery.Set("state", "xyz")
	plainQuery.Set("code_challenge", challenge)
	plainQuery.Set("code_challenge_method", "S256")
	plainAuth, err := browser.Get(ts.URL + "/oauth/authorize?" + plainQuery.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = plainAuth.Body.Close()
	if plainAuth.StatusCode != http.StatusFound {
		t.Fatalf("plain authorize %d %s", plainAuth.StatusCode, plainAuth.Header.Get("Location"))
	}
	plainLoc, err := url.Parse(plainAuth.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	plainCode := plainLoc.Query().Get("code")
	if plainCode == "" {
		t.Fatalf("plain location %s", plainAuth.Header.Get("Location"))
	}
	stray := exchangeCode(t, ts.URL, app.ID, plainCode, verifier, actorToken)
	if stray.Status != http.StatusBadRequest || !strings.Contains(stray.Body, "not allowed") {
		t.Fatalf("stray actor token %d %s", stray.Status, stray.Body)
	}
}

type registeredClient struct {
	ID     string
	Secret string
}

func registerClient(t *testing.T, base, body string) registeredClient {
	t.Helper()
	resp, err := http.Post(base+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var client struct {
		ID     string `json:"client_id"`
		Secret string `json:"client_secret"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register %d %s", resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, &client); err != nil {
		t.Fatal(err)
	}
	return registeredClient{ID: client.ID, Secret: client.Secret}
}

func clientCredentialsToken(t *testing.T, base, id, secret string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader("grant_type=client_credentials&scope=openid"))
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
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	token, _ := body["access_token"].(string)
	if resp.StatusCode != http.StatusOK || token == "" {
		t.Fatalf("actor token %d %v", resp.StatusCode, body)
	}
	return token
}

func actorAuthorizeQuery(clientID, actorID, challenge, method string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", "https://app.example/cb")
	q.Set("scope", "openid")
	q.Set("state", "xyz")
	q.Set("requested_actor", actorID)
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", method)
	}
	return q.Encode()
}

func exchangeCode(t *testing.T, base, clientID, code, verifier, actorToken string) tokenResult {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("code_verifier", verifier)
	form.Set("client_id", clientID)
	if actorToken != "" {
		form.Set("actor_token", actorToken)
	}
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
