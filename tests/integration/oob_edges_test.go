package integration

import (
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

func TestOutOfBandAutoShowsTheCode(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	createUser(t, ts.URL, token)

	const redirectURI = "urn:ietf:wg:oauth:2.0:oob:auto"
	regBody := `{"client_name":"CLI","redirect_uris":["` + redirectURI + `"],"grant_types":["authorization_code"],"scope":"openid","token_endpoint_auth_method":"none"}`
	client := registerClient(t, ts.URL, regBody)

	verifier, err := crypto.GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge := crypto.GenerateCodeChallenge(verifier)
	implicit := url.Values{}
	implicit.Set("client_id", client.ID)
	implicit.Set("response_type", "token")
	implicit.Set("redirect_uri", redirectURI)
	implicit.Set("scope", "openid")
	implicit.Set("state", "xyz")
	implicit.Set("code_challenge", challenge)
	implicit.Set("code_challenge_method", "S256")
	rejected, err := http.Get(ts.URL + "/oauth/authorize?" + implicit.Encode())
	if err != nil {
		t.Fatal(err)
	}
	rejectedBody, _ := io.ReadAll(rejected.Body)
	_ = rejected.Body.Close()
	if rejected.StatusCode != http.StatusBadRequest || !strings.Contains(string(rejectedBody), "response_type code") {
		t.Fatalf("implicit %d %s", rejected.StatusCode, rejectedBody)
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

	page := followConsent(t, browser, ts, "/oauth/authorize?"+authorizeQuery(client.ID, redirectURI, challenge, "S256"), "approve")
	if page.StatusCode != http.StatusOK || page.Location != "" || !strings.Contains(page.CacheControl, "no-store") {
		t.Fatalf("page %d location %q cache %q", page.StatusCode, page.Location, page.CacheControl)
	}
	code := inputValue(t, page.Body, "authorization-code")
	wrong := tokenFromCode(t, ts.URL, client.ID, code, verifier, "urn:ietf:wg:oauth:2.0:oob")
	if wrong.Status != http.StatusBadRequest || !strings.Contains(wrong.Body, "redirect_uri") {
		t.Fatalf("wrong urn %d %s", wrong.Status, wrong.Body)
	}
	issued := tokenFromCode(t, ts.URL, client.ID, code, verifier, redirectURI)
	if issued.Status != http.StatusOK || issued.Access == "" {
		t.Fatalf("token %d %s", issued.Status, issued.Body)
	}
	replay := tokenFromCode(t, ts.URL, client.ID, code, verifier, redirectURI)
	if replay.Status == http.StatusOK {
		t.Fatalf("replay succeeded %s", replay.Body)
	}
}

func TestOOBHelperRejectsPartialQuery(t *testing.T) {
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	cfg.Security.OOBHelper = true
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(10))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.GetRouter())
	defer ts.Close()

	missing, err := http.Get(ts.URL + "/oauth/oob")
	if err != nil {
		t.Fatal(err)
	}
	missingBody, _ := io.ReadAll(missing.Body)
	_ = missing.Body.Close()
	if missing.StatusCode != http.StatusBadRequest || !strings.Contains(string(missingBody), "code and state") {
		t.Fatalf("missing %d %s", missing.StatusCode, missingBody)
	}

	onlyCode, err := http.Get(ts.URL + "/oauth/oob?code=abc")
	if err != nil {
		t.Fatal(err)
	}
	_ = onlyCode.Body.Close()
	if onlyCode.StatusCode != http.StatusBadRequest {
		t.Fatalf("code only %d", onlyCode.StatusCode)
	}

	failed, err := http.Get(ts.URL + "/oauth/oob?error=access_denied&error_description=nope&state=xyz")
	if err != nil {
		t.Fatal(err)
	}
	failedBody, _ := io.ReadAll(failed.Body)
	_ = failed.Body.Close()
	if failed.StatusCode != http.StatusOK || !strings.Contains(string(failedBody), "access_denied") || strings.Contains(string(failedBody), `id="combined-code"`) {
		t.Fatalf("error page %d %s", failed.StatusCode, failedBody)
	}
	if !strings.Contains(failed.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("error cache %q", failed.Header.Get("Cache-Control"))
	}

	page, err := http.Get(ts.URL + "/oauth/oob?code=abc&state=xyz")
	if err != nil {
		t.Fatal(err)
	}
	pageBody, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(page.Header.Get("Cache-Control"), "no-store") {
		t.Fatalf("helper %d cache %q", page.StatusCode, page.Header.Get("Cache-Control"))
	}
	recovered, err := oobcode.Recover(inputValue(t, string(pageBody), "combined-code"), "xyz")
	if err != nil || recovered != "abc" {
		t.Fatalf("recovered %q err=%v", recovered, err)
	}
}
