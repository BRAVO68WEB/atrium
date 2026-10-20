package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/pquerna/otp/totp"
)

func TestAuthorizePromptNoneAndBadPKCE(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	mgmt := managementToken(t, ts.URL)
	createAPIUser(t, ts.URL, mgmt, "ada", "ada@example.com", true)
	client := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":                       "Notes",
		"redirect_uris":              []string{"https://app.example/cb"},
		"grant_types":                []string{"authorization_code"},
		"scopes":                     []string{"openid"},
		"token_endpoint_auth_method": "none",
	})
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", client["id"].(string))
	query.Set("redirect_uri", "https://app.example/cb")
	query.Set("scope", "openid")
	query.Set("state", "edge")
	query.Set("prompt", "none")
	noneResp, err := http.Get(ts.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	noneBody := readBody(t, noneResp)
	if noneResp.StatusCode != http.StatusFound || !strings.Contains(noneBody, "login_required") {
		t.Fatalf("prompt none %d %s", noneResp.StatusCode, noneBody)
	}

	browser := browserClient()
	login := url.Values{}
	login.Set("username", "ada")
	login.Set("password", "correct-horse")
	login.Set("csrf_token", csrfToken(t, browser, ts.URL+"/login"))
	loginResp, err := browser.PostForm(ts.URL+"/login", login)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()
	query.Set("prompt", "login")
	again, err := browser.Get(ts.URL + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = again.Body.Close()
	if again.StatusCode != http.StatusFound || !strings.Contains(again.Header.Get("Location"), "/login") {
		t.Fatalf("prompt login %d %s", again.StatusCode, again.Header.Get("Location"))
	}

	bad := url.Values{}
	bad.Set("response_type", "code")
	bad.Set("client_id", client["id"].(string))
	bad.Set("redirect_uri", "https://app.example/cb")
	bad.Set("code_challenge", "abc")
	bad.Set("code_challenge_method", "S512")
	badResp, err := http.Get(ts.URL + "/oauth/authorize?" + bad.Encode())
	if err != nil {
		t.Fatal(err)
	}
	badBody := readBody(t, badResp)
	if badResp.StatusCode != http.StatusBadRequest || !strings.Contains(badBody, "invalid_request") {
		t.Fatalf("pkce %d %s", badResp.StatusCode, badBody)
	}
}

func TestMFAEnrollPageAcceptsAValidCode(t *testing.T) {
	ts := setupConfigured(t, func(cfg *config.Config) {
		cfg.Security.MFA.Required = true
	})
	mgmt := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, mgmt)
	createAPIUser(t, ts.URL, mgmt, "otto", "otto@example.com", true)

	ada := signInFollowing(t, ts.URL, "ada", "correct horse")
	secret := formValue(t, ada.body, "secret")
	wrongCode := "000000"
	if secret == wrongCode {
		wrongCode = "111111"
	}
	wrong := url.Values{}
	wrong.Set("csrf_token", csrfFromBody(t, ada.body))
	wrong.Set("secret", secret)
	wrong.Set("code", wrongCode)
	bad, err := ada.browser.PostForm(ts.URL+"/mfa/enroll/verify", wrong)
	if err != nil {
		t.Fatal(err)
	}
	badBody := readBody(t, bad)
	if !strings.Contains(badBody, "Invalid code") {
		t.Fatalf("wrong code %s", badBody)
	}

	otto := signInFollowing(t, ts.URL, "otto", "correct-horse")
	goodSecret := formValue(t, otto.body, "secret")
	code, err := totp.GenerateCode(goodSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("csrf_token", csrfFromBody(t, otto.body))
	form.Set("secret", goodSecret)
	form.Set("code", code)
	ok, err := otto.browser.PostForm(ts.URL+"/mfa/enroll/verify", form)
	if err != nil {
		t.Fatal(err)
	}
	okBody, _ := io.ReadAll(ok.Body)
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusFound {
		t.Fatalf("confirm %d %s", ok.StatusCode, okBody)
	}
}

type followedLogin struct {
	browser *http.Client
	body    string
}

func signInMFA(t *testing.T, base, username, password string) *http.Client {
	t.Helper()
	browser := browserClient()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	form.Set("csrf_token", csrfToken(t, browser, base+"/login"))
	resp, err := browser.PostForm(base+"/login", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/mfa/enroll") {
		t.Fatalf("login %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	return browser
}

func signInFollowing(t *testing.T, base, username, password string) followedLogin {
	t.Helper()
	browser := signInMFA(t, base, username, password)
	resp, err := browser.Get(base + "/mfa/enroll")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "secret-box") {
		t.Fatalf("enroll page %d %s", resp.StatusCode, body)
	}
	return followedLogin{browser: browser, body: body}
}
