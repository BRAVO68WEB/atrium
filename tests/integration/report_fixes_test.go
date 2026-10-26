package integration

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func TestReportFixes(t *testing.T) {
	ts := setupConfigured(t, nil)
	mgmt := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, mgmt)
	app := registerClient(t, ts.URL, `{"client_name":"Report","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code","refresh_token","implicit"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic","dpop_bound_access_tokens":true,"require_pushed_authorization_requests":true}`)

	discResp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	discBody, _ := io.ReadAll(discResp.Body)
	_ = discResp.Body.Close()
	if strings.Contains(string(discBody), `"none"`) && strings.Contains(string(discBody), "request_object_signing_alg_values_supported") {
		var disc map[string]any
		_ = json.Unmarshal(discBody, &disc)
		algs, _ := disc["request_object_signing_alg_values_supported"].([]any)
		for _, alg := range algs {
			if alg == "none" {
				t.Fatal("discovery still advertises unsigned request objects")
			}
		}
	}

	open := registerClient(t, ts.URL, `{"client_name":"Open","redirect_uris":["https://app.example/cb"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"none"}`)
	missingRedirect := url.Values{}
	missingRedirect.Set("response_type", "code")
	missingRedirect.Set("client_id", open.ID)
	missingRedirect.Set("scope", "openid")
	missingRedirect.Set("code_challenge", crypto.GenerateCodeChallenge(strings.Repeat("a", 43)))
	missingRedirect.Set("code_challenge_method", "S256")
	noURI, err := http.Get(ts.URL + "/oauth/authorize?" + missingRedirect.Encode())
	if err != nil {
		t.Fatal(err)
	}
	noURIBody, _ := io.ReadAll(noURI.Body)
	_ = noURI.Body.Close()
	if noURI.StatusCode != http.StatusBadRequest || !strings.Contains(string(noURIBody), "redirect_uri is required") {
		t.Fatalf("missing redirect %d %s", noURI.StatusCode, noURIBody)
	}

	direct := url.Values{}
	direct.Set("response_type", "code")
	direct.Set("client_id", app.ID)
	direct.Set("redirect_uri", "https://app.example/cb")
	direct.Set("scope", "openid")
	direct.Set("code_challenge", crypto.GenerateCodeChallenge(strings.Repeat("a", 43)))
	direct.Set("code_challenge_method", "S256")
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	skippedPAR, err := noFollow.Get(ts.URL + "/oauth/authorize?" + direct.Encode())
	if err != nil {
		t.Fatal(err)
	}
	skippedBody, _ := io.ReadAll(skippedPAR.Body)
	_ = skippedPAR.Body.Close()
	skippedLoc := skippedPAR.Header.Get("Location")
	if skippedPAR.StatusCode != http.StatusFound || !strings.HasPrefix(skippedLoc, "https://app.example/cb?") || !strings.Contains(skippedLoc, "error=invalid_request") || !strings.Contains(skippedLoc, "request_uri") {
		t.Fatalf("par not required %d %s %s", skippedPAR.StatusCode, skippedLoc, skippedBody)
	}

	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", app.ID)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("scope", "openid")
	form.Set("state", "posted")
	form.Set("code_challenge", crypto.GenerateCodeChallenge(strings.Repeat("b", 43)))
	form.Set("code_challenge_method", "S256")
	postReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	posted, err := noFollow.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	postedBody, _ := io.ReadAll(posted.Body)
	_ = posted.Body.Close()
	postedLoc := posted.Header.Get("Location")
	if posted.StatusCode != http.StatusFound || !strings.HasPrefix(postedLoc, "https://app.example/cb?") || !strings.Contains(postedLoc, "error=invalid_request") || !strings.Contains(postedLoc, "request_uri") || !strings.Contains(postedLoc, "state=posted") {
		t.Fatalf("post authorize %d %s %s", posted.StatusCode, postedLoc, postedBody)
	}

	dup := form.Encode() + "&scope=openid"
	dupReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/authorize", strings.NewReader(dup))
	dupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dupResp, err := noFollow.Do(dupReq)
	if err != nil {
		t.Fatal(err)
	}
	dupBody, _ := io.ReadAll(dupResp.Body)
	_ = dupResp.Body.Close()
	dupLoc := dupResp.Header.Get("Location")
	if dupResp.StatusCode != http.StatusFound || !strings.HasPrefix(dupLoc, "https://app.example/cb?") || !strings.Contains(dupLoc, "error=invalid_request") || !strings.Contains(dupLoc, "Duplicate") {
		t.Fatalf("duplicate %d %s %s", dupResp.StatusCode, dupLoc, dupBody)
	}
	conflict := form.Encode() + "&redirect_uri=" + url.QueryEscape("https://evil.example/cb")
	conflictReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/authorize", strings.NewReader(conflict))
	conflictReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	conflictResp, err := noFollow.Do(conflictReq)
	if err != nil {
		t.Fatal(err)
	}
	conflictBody, _ := io.ReadAll(conflictResp.Body)
	_ = conflictResp.Body.Close()
	if conflictResp.StatusCode != http.StatusBadRequest || conflictResp.Header.Get("Location") != "" || !strings.Contains(string(conflictBody), "Duplicate") {
		t.Fatalf("conflicting redirect %d %s %s", conflictResp.StatusCode, conflictResp.Header.Get("Location"), conflictBody)
	}

	secretInURI := ts.URL + "/oauth/token?client_id=" + url.QueryEscape(app.ID) + "&client_secret=" + url.QueryEscape(app.Secret)
	leaked, err := http.Post(secretInURI, "application/x-www-form-urlencoded", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatal(err)
	}
	leakedBody, _ := io.ReadAll(leaked.Body)
	_ = leaked.Body.Close()
	if leaked.StatusCode != http.StatusBadRequest || !strings.Contains(string(leakedBody), "request URI") {
		t.Fatalf("secret in uri %d %s", leaked.StatusCode, leakedBody)
	}

	verifier := strings.Repeat("c", 43)
	par := url.Values{}
	par.Set("response_type", "code")
	par.Set("client_id", app.ID)
	par.Set("redirect_uri", "https://app.example/cb")
	par.Set("scope", "openid")
	par.Set("state", "par-state")
	par.Set("nonce", "n")
	par.Set("code_challenge", crypto.GenerateCodeChallenge(verifier))
	par.Set("code_challenge_method", "S256")
	par.Set("response_mode", "form_post")
	parReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/par", strings.NewReader(par.Encode()))
	parReq.SetBasicAuth(app.ID, app.Secret)
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parResp, err := http.DefaultClient.Do(parReq)
	if err != nil {
		t.Fatal(err)
	}
	var pushed map[string]any
	_ = json.NewDecoder(parResp.Body).Decode(&pushed)
	_ = parResp.Body.Close()
	requestURI, _ := pushed["request_uri"].(string)
	if parResp.StatusCode != http.StatusCreated || requestURI == "" {
		t.Fatalf("par %d %+v", parResp.StatusCode, pushed)
	}
	repeatedClient := ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(app.ID) + "&request_uri=" + url.QueryEscape(requestURI) + "&client_id=" + url.QueryEscape(app.ID)
	repeated, err := noFollow.Get(repeatedClient)
	if err != nil {
		t.Fatal(err)
	}
	repeatedBody, _ := io.ReadAll(repeated.Body)
	_ = repeated.Body.Close()
	if repeated.StatusCode != http.StatusOK || !strings.Contains(string(repeatedBody), "https://app.example/cb") || !strings.Contains(string(repeatedBody), "invalid_request") {
		t.Fatalf("duplicate client_id %d %s", repeated.StatusCode, repeatedBody)
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

	authResp, authBody := followAuthorize(t, browser, ts.URL+"/oauth/authorize?client_id="+url.QueryEscape(app.ID)+"&request_uri="+url.QueryEscape(requestURI))
	if authResp.StatusCode != http.StatusOK || !strings.Contains(string(authBody), `method="post"`) {
		t.Fatalf("form_post %d %s", authResp.StatusCode, authBody)
	}
	code := hiddenValue(t, string(authBody), "code")
	if code == "" {
		t.Fatalf("missing code in %s", authBody)
	}

	again, err := browser.Get(ts.URL + "/oauth/authorize?client_id=" + url.QueryEscape(app.ID) + "&request_uri=" + url.QueryEscape(requestURI))
	if err != nil {
		t.Fatal(err)
	}
	againBody, _ := io.ReadAll(again.Body)
	_ = again.Body.Close()
	if again.StatusCode != http.StatusOK || !strings.Contains(string(againBody), "invalid_request") || !strings.Contains(string(againBody), "https://app.example/cb") || strings.Contains(string(againBody), `name="code"`) {
		t.Fatalf("reused request_uri %d %s", again.StatusCode, againBody)
	}

	dpop := service.NewDPoPService()
	key, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortForm := url.Values{}
	shortForm.Set("grant_type", "authorization_code")
	shortForm.Set("code", code)
	shortForm.Set("redirect_uri", "https://app.example/cb")
	shortForm.Set("code_verifier", "abc")
	shortReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(shortForm.Encode()))
	shortReq.SetBasicAuth(app.ID, app.Secret)
	shortReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	shortProof, err := dpop.CreateDPoPProof(key, http.MethodPost, ts.URL+"/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	shortReq.Header.Set("DPoP", shortProof)
	shortResp, err := http.DefaultClient.Do(shortReq)
	if err != nil {
		t.Fatal(err)
	}
	shortBody, _ := io.ReadAll(shortResp.Body)
	_ = shortResp.Body.Close()
	if shortResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short verifier %d %s", shortResp.StatusCode, shortBody)
	}

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("redirect_uri", "https://app.example/cb")
	tokenForm.Set("code_verifier", verifier)
	tokenReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.SetBasicAuth(app.ID, app.Secret)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenProof, err := dpop.CreateDPoPProof(key, http.MethodPost, ts.URL+"/oauth/token", "")
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.Header.Set("DPoP", tokenProof)
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	_ = json.NewDecoder(tokenResp.Body).Decode(&token)
	_ = tokenResp.Body.Close()
	access, _ := token["access_token"].(string)
	issuedID, _ := token["id_token"].(string)
	if tokenResp.StatusCode != http.StatusOK || token["token_type"] != "DPoP" || access == "" {
		t.Fatalf("token %d %+v", tokenResp.StatusCode, token)
	}
	if !idTokenHasHash(t, issuedID, "at_hash", oidc.TokenHash(access)) || !idTokenHasHash(t, issuedID, "c_hash", oidc.TokenHash(code)) {
		t.Fatalf("hashes %s", issuedID)
	}

	reuseForm := url.Values{}
	reuseForm.Set("grant_type", "authorization_code")
	reuseForm.Set("code", code)
	reuseForm.Set("redirect_uri", "https://app.example/cb")
	reuseForm.Set("code_verifier", verifier)
	reuseReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/oauth/token", strings.NewReader(reuseForm.Encode()))
	reuseReq.SetBasicAuth(app.ID, app.Secret)
	reuseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseProof, _ := dpop.CreateDPoPProof(key, http.MethodPost, ts.URL+"/oauth/token", "")
	reuseReq.Header.Set("DPoP", reuseProof)
	reuseResp, err := http.DefaultClient.Do(reuseReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = reuseResp.Body.Close()
	if reuseResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reuse %d", reuseResp.StatusCode)
	}
	if userinfoStatus(t, dpop, key, ts.URL, access) != http.StatusUnauthorized {
		t.Fatal("reused code left the access token alive")
	}

	// A second token, then revoke it.
	secondURI := pushPAR(t, ts.URL, app.ID, app.Secret, crypto.GenerateCodeChallenge(verifier))
	_, secondBody := followAuthorize(t, browser, ts.URL+"/oauth/authorize?client_id="+url.QueryEscape(app.ID)+"&request_uri="+url.QueryEscape(secondURI))
	secondCode := hiddenValue(t, string(secondBody), "code")
	secondToken := exchangeDPoPCode(t, dpop, key, ts.URL, app.ID, app.Secret, secondCode, verifier)
	revokeToken(t, dpop, key, ts.URL, app.ID, app.Secret, secondToken)
	if userinfoStatus(t, dpop, key, ts.URL, secondToken) != http.StatusUnauthorized {
		t.Fatal("revoked access token still works")
	}
}

func followAuthorize(t *testing.T, browser *http.Client, rawURL string) (*http.Response, []byte) {
	t.Helper()
	for range 6 {
		resp, err := browser.Get(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			return resp, body
		}
		next := resp.Header.Get("Location")
		if strings.HasPrefix(next, "/") {
			next = resp.Request.URL.Scheme + "://" + resp.Request.Host + next
		}
		if strings.Contains(next, "/consent") {
			page, err := browser.Get(next)
			if err != nil {
				t.Fatal(err)
			}
			pageBody, _ := io.ReadAll(page.Body)
			_ = page.Body.Close()
			parsed, err := url.Parse(next)
			if err != nil {
				t.Fatal(err)
			}
			approve := parsed.Query()
			approve.Set("csrf_token", csrfFromBody(t, string(pageBody)))
			approve.Set("action", "approve")
			approved, err := browser.PostForm(strings.Split(next, "/consent")[0]+"/consent", approve)
			if err != nil {
				t.Fatal(err)
			}
			approvedBody, _ := io.ReadAll(approved.Body)
			_ = approved.Body.Close()
			if approved.StatusCode != http.StatusFound {
				return approved, approvedBody
			}
			next = approved.Header.Get("Location")
			if strings.HasPrefix(next, "/") {
				next = approved.Request.URL.Scheme + "://" + approved.Request.Host + next
			}
		}
		rawURL = next
	}
	t.Fatal("authorize did not finish")
	return nil, nil
}

func pushPAR(t *testing.T, base, id, secret, challenge string) string {
	t.Helper()
	par := url.Values{}
	par.Set("response_type", "code")
	par.Set("redirect_uri", "https://app.example/cb")
	par.Set("scope", "openid")
	par.Set("code_challenge", challenge)
	par.Set("code_challenge_method", "S256")
	par.Set("response_mode", "form_post")
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/par", strings.NewReader(par.Encode()))
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	uri, _ := body["request_uri"].(string)
	if resp.StatusCode != http.StatusCreated || uri == "" {
		t.Fatalf("par %d %+v", resp.StatusCode, body)
	}
	return uri
}

func exchangeDPoPCode(t *testing.T, dpop *service.DPoPService, key *ecdsa.PrivateKey, base, id, secret, code, verifier string) string {
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
	if resp.StatusCode != http.StatusOK || access == "" {
		t.Fatalf("exchange %d %+v", resp.StatusCode, token)
	}
	return access
}

func revokeToken(t *testing.T, dpop *service.DPoPService, key *ecdsa.PrivateKey, base, id, secret, token string) {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	req, _ := http.NewRequest(http.MethodPost, base+"/oauth/revoke", strings.NewReader(form.Encode()))
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proof, err := dpop.CreateDPoPProof(key, http.MethodPost, base+"/oauth/revoke", token)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", proof)
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

func userinfoStatus(t *testing.T, dpop *service.DPoPService, key *ecdsa.PrivateKey, base, access string) int {
	t.Helper()
	proof, err := dpop.CreateDPoPProof(key, http.MethodGet, base+"/oidc/userinfo", access)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/oidc/userinfo", nil)
	req.Header.Set("Authorization", "DPoP "+access)
	req.Header.Set("DPoP", proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func hiddenValue(t *testing.T, body, name string) string {
	t.Helper()
	needle := `name="` + name + `" value="`
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	rest := body[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func idTokenHasHash(t *testing.T, raw, claim, want string) bool {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}
	got, _ := claims[claim].(string)
	return got == want
}
