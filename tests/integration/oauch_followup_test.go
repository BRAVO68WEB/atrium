package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/pkg/crypto"
	"github.com/golang-jwt/jwt/v5"
)

func TestPARAcceptsARedirectURIThatWasNotRegistered(t *testing.T) {
	ts := setupConfigured(t, nil)
	app := registerClient(t, ts.URL, `{"client_name":"Mint","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	public := registerClient(t, ts.URL, `{"client_name":"Public","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"none"}`)
	minted := "https://app.example/cb/Modified"
	status, body := postBasic(t, ts.URL+"/oauth/par", app.ID, app.Secret, url.Values{
		"response_type": {"code"},
		"redirect_uri":  {minted},
		"scope":         {"openid"},
		"state":         {"par"},
	})
	if status != http.StatusCreated || !strings.Contains(body, "request_uri") {
		t.Fatalf("confidential par %d %s", status, body)
	}
	var pushed map[string]any
	if err := json.Unmarshal([]byte(body), &pushed); err != nil {
		t.Fatalf("par body %s", body)
	}
	requestURI, _ := pushed["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("par body %s", body)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	direct, err := noFollow.Get(ts.URL + "/oauth/authorize?response_type=code&client_id=" + url.QueryEscape(app.ID) + "&redirect_uri=" + url.QueryEscape(minted) + "&scope=openid")
	if err != nil {
		t.Fatal(err)
	}
	directBody, _ := io.ReadAll(direct.Body)
	_ = direct.Body.Close()
	if direct.StatusCode != http.StatusBadRequest || !strings.Contains(string(directBody), "Invalid redirect_uri") {
		t.Fatalf("direct authorize %d %s", direct.StatusCode, directBody)
	}
	followed, err := noFollow.Get(ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(app.ID) + "&request_uri=" + url.QueryEscape(requestURI))
	if err != nil {
		t.Fatal(err)
	}
	_ = followed.Body.Close()
	if followed.StatusCode != http.StatusFound || !strings.Contains(followed.Header.Get("Location"), "/login") {
		t.Fatalf("par authorize %d %s", followed.StatusCode, followed.Header.Get("Location"))
	}
	pub, err := http.PostForm(ts.URL+"/oauth/par", url.Values{
		"response_type": {"code"},
		"client_id":     {public.ID},
		"redirect_uri":  {minted},
		"scope":         {"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pubBody, _ := io.ReadAll(pub.Body)
	_ = pub.Body.Close()
	if pub.StatusCode != http.StatusBadRequest || !strings.Contains(string(pubBody), "Invalid redirect_uri") {
		t.Fatalf("public par %d %s", pub.StatusCode, pubBody)
	}
}

func TestRequestURIIsBoundToThePushingClient(t *testing.T) {
	ts := setupBound(t, nil)
	owner := registerClient(t, ts.URL, `{"client_name":"Owner","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	other := registerClient(t, ts.URL, `{"client_name":"Other","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	verifier := strings.Repeat("a", 43)
	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", owner.ID)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("scope", "openid")
	form.Set("state", "bound")
	form.Set("code_challenge", crypto.GenerateCodeChallenge(verifier))
	form.Set("code_challenge_method", "S256")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/par", strings.NewReader(form.Encode()))
	req.SetBasicAuth(owner.ID, owner.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var pushed map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pushed)
	_ = resp.Body.Close()
	requestURI, _ := pushed["request_uri"].(string)
	if resp.StatusCode != http.StatusCreated || requestURI == "" {
		t.Fatalf("par %d %+v", resp.StatusCode, pushed)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(other.ID) + "&request_uri=" + url.QueryEscape(requestURI)
	got, err := noFollow.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	loc := got.Header.Get("Location")
	if got.StatusCode != http.StatusFound || !strings.Contains(loc, "error=invalid_request") || !strings.Contains(loc, "does+not+match") {
		t.Fatalf("wrong client %d %s %s", got.StatusCode, loc, body)
	}
}

func TestClientSecretJWTAuthenticatesAndRejectsReplay(t *testing.T) {
	ts := setupBound(t, nil)
	app := registerClient(t, ts.URL, `{"client_name":"JWT","redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	raw := clientAssertion(t, jwt.SigningMethodHS256, []byte(app.Secret), "", app.ID, ts.URL+"/oauth/token", "jti-1")
	first := assertionToken(t, ts.URL, raw)
	if first["access_token"] == "" {
		t.Fatalf("token %v", first)
	}
	second := assertionToken(t, ts.URL, raw)
	if second["error"] != "invalid_client" {
		t.Fatalf("replay %v", second)
	}
}

func TestPrivateKeyJWTAuthenticates(t *testing.T) {
	ts := setupBound(t, nil)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": "app-key",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	encoded, _ := json.Marshal(jwks)
	mgmt := managementToken(t, ts.URL)
	created := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":                       "Private",
		"redirect_uris":              []string{"https://app.example/cb"},
		"grant_types":                []string{"client_credentials"},
		"scopes":                     []string{"openid"},
		"token_endpoint_auth_method": "client_secret_basic",
		"jwks":                       string(encoded),
	})
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("client %v", created)
	}
	raw := clientAssertion(t, jwt.SigningMethodRS256, key, "app-key", id, ts.URL+"/oauth/token", "pk-jti")
	got := assertionToken(t, ts.URL, raw)
	if got["access_token"] == "" {
		t.Fatalf("private key jwt %v", got)
	}
}

func TestConfidentialClientRevokesADPoPTokenWithoutAProof(t *testing.T) {
	ts := setupBound(t, nil)
	app := registerClient(t, ts.URL, `{"client_name":"Bound","redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic","dpop_bound_access_tokens":true}`)
	other := registerClient(t, ts.URL, `{"client_name":"Stranger","redirect_uris":["https://app.example/cb"],"grant_types":["client_credentials"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpop := service.NewDPoPService()
	proof, err := dpop.CreateDPoPProof(key, http.MethodPost, ts.URL+"/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(form.Encode()))
	req.SetBasicAuth(app.ID, app.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var issued map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&issued)
	_ = resp.Body.Close()
	access, _ := issued["access_token"].(string)
	if resp.StatusCode != http.StatusOK || access == "" {
		t.Fatalf("issue %d %v", resp.StatusCode, issued)
	}
	steal := url.Values{}
	steal.Set("token", access)
	stealReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/revoke", strings.NewReader(steal.Encode()))
	stealReq.SetBasicAuth(other.ID, other.Secret)
	stealReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	stealResp, err := http.DefaultClient.Do(stealReq)
	if err != nil {
		t.Fatal(err)
	}
	stealBody, _ := io.ReadAll(stealResp.Body)
	_ = stealResp.Body.Close()
	if stealResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(stealBody), "another client") || !introspectActive(t, ts.URL, app, access) {
		t.Fatalf("wrong client %d %s", stealResp.StatusCode, stealBody)
	}
	revoke := url.Values{}
	revoke.Set("token", access)
	revokeReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/revoke", strings.NewReader(revoke.Encode()))
	revokeReq.SetBasicAuth(app.ID, app.Secret)
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(revokeResp.Body)
	_ = revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke %d %s", revokeResp.StatusCode, raw)
	}
	if introspectActive(t, ts.URL, app, access) {
		t.Fatal("token stayed active")
	}
}

func TestUsedCodeRevokesEvenWithoutDPoP(t *testing.T) {
	ts := setupConfigured(t, nil)
	mgmt := managementToken(t, ts.URL)
	createUser(t, ts.URL, mgmt)
	app := registerClient(t, ts.URL, `{"client_name":"Reuse","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code","refresh_token"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic","dpop_bound_access_tokens":true}`)
	verifier := strings.Repeat("c", 43)
	requestURI := pushPAR(t, ts.URL, app.ID, app.Secret, crypto.GenerateCodeChallenge(verifier))
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct horse")
	login.Set("csrf_token", csrfToken(t, browser, ts.URL+"/login"))
	loginResp, err := browser.PostForm(ts.URL+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()
	authResp, authBody := followAuthorize(t, browser, ts.URL+"/oauth/authorize?client_id="+url.QueryEscape(app.ID)+"&request_uri="+url.QueryEscape(requestURI))
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("authorize %d %s", authResp.StatusCode, authBody)
	}
	code := hiddenValue(t, string(authBody), "code")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpop := service.NewDPoPService()
	access, refresh := exchangeCodePair(t, dpop, key, ts.URL, app.ID, app.Secret, code, verifier)
	again := url.Values{}
	again.Set("grant_type", "authorization_code")
	again.Set("code", code)
	again.Set("redirect_uri", "https://app.example/cb")
	again.Set("code_verifier", verifier)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(again.Encode()))
	req.SetBasicAuth(app.ID, app.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "already used") {
		t.Fatalf("reuse %d %s", resp.StatusCode, body)
	}
	if userinfoStatus(t, dpop, key, ts.URL, access) != http.StatusUnauthorized {
		t.Fatal("access token stayed active")
	}
	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refresh)
	refreshReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.SetBasicAuth(app.ID, app.Secret)
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshResp, err := http.DefaultClient.Do(refreshReq)
	if err != nil {
		t.Fatal(err)
	}
	refreshBody, _ := io.ReadAll(refreshResp.Body)
	_ = refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(refreshBody), "invalid_grant") {
		t.Fatalf("refresh %d %s", refreshResp.StatusCode, refreshBody)
	}
}

func TestRequestObjectSuppliesTheAuthorizationParameters(t *testing.T) {
	ts := setupBound(t, nil)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "jar", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	mgmt := managementToken(t, ts.URL)
	owner := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name": "JAR", "redirect_uris": []string{"https://app.example/cb"},
		"grant_types": []string{"authorization_code"}, "scopes": []string{"openid"},
		"token_endpoint_auth_method": "client_secret_basic", "jwks": string(jwks),
	})
	other := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name": "Other JAR", "redirect_uris": []string{"https://app.example/cb"},
		"grant_types": []string{"authorization_code"}, "scopes": []string{"openid"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	ownerID := owner["id"].(string)
	secret := owner["secret"].(string)
	challenge := crypto.GenerateCodeChallenge(strings.Repeat("d", 43))
	omitted := signedRequest(t, key, "jar", jwt.MapClaims{
		"iss": ownerID, "aud": ts.URL, "exp": time.Now().Add(time.Hour).Unix(),
		"client_id": ownerID, "redirect_uri": "https://app.example/cb", "scope": "openid",
		"code_challenge": challenge, "code_challenge_method": "S256",
	})
	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("request", omitted)
	status, body := postBasic(t, ts.URL+"/oauth/par", ownerID, secret, form)
	if status != http.StatusBadRequest || !strings.Contains(body, "response_type") {
		t.Fatalf("omitted response_type %d %s", status, body)
	}
	mismatch := signedRequest(t, key, "jar", jwt.MapClaims{
		"iss": ownerID, "aud": ts.URL, "exp": time.Now().Add(time.Hour).Unix(),
		"client_id": other["id"], "response_type": "code",
		"redirect_uri": "https://app.example/cb", "scope": "openid",
		"code_challenge": challenge, "code_challenge_method": "S256",
	})
	form.Set("request", mismatch)
	status, body = postBasic(t, ts.URL+"/oauth/par", ownerID, secret, form)
	if status != http.StatusBadRequest || !strings.Contains(body, "client_id") {
		t.Fatalf("client_id mismatch %d %s", status, body)
	}
	good := signedRequest(t, key, "jar", jwt.MapClaims{
		"iss": ownerID, "aud": ts.URL, "exp": time.Now().Add(time.Hour).Unix(),
		"client_id": ownerID, "response_type": "code",
		"redirect_uri": "https://app.example/cb", "scope": "openid",
		"code_challenge": challenge, "code_challenge_method": "S256",
	})
	form.Set("request", good)
	status, body = postBasic(t, ts.URL+"/oauth/par", ownerID, secret, form)
	if status != http.StatusCreated || !strings.Contains(body, "request_uri") {
		t.Fatalf("signed request %d %s", status, body)
	}
}

func exchangeCodePair(t *testing.T, dpop *service.DPoPService, key *ecdsa.PrivateKey, base, id, secret, code, verifier string) (string, string) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("code_verifier", verifier)
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proof, err := dpop.CreateDPoPProof(key, http.MethodPost, base+"/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var token map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&token)
	access, _ := token["access_token"].(string)
	refresh, _ := token["refresh_token"].(string)
	if resp.StatusCode != http.StatusOK || access == "" || refresh == "" {
		t.Fatalf("exchange %d %+v", resp.StatusCode, token)
	}
	return access, refresh
}

func signedRequest(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func postBasic(t *testing.T, rawURL, id, secret string, form url.Values) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func clientAssertion(t *testing.T, method jwt.SigningMethod, key any, kid, clientID, aud, jti string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": aud,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-5 * time.Second).Unix(),
		"jti": jti,
	})
	if kid != "" {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertionToken(t *testing.T, base, assertion string) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	resp, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		body["error"] = body["error"]
		if body["error"] == nil {
			body["error"] = "status"
		}
	}
	return body
}

func introspectActive(t *testing.T, base string, app registeredClient, token string) bool {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/introspect", strings.NewReader(form.Encode()))
	req.SetBasicAuth(app.ID, app.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body["active"] == true
}
