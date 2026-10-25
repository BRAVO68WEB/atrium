package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
)

func TestOrganizationsStayOffUntilEnabled(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementAccessToken(t, ts.URL)
	status, raw := apiCall(t, http.MethodPost, ts.URL+"/api/orgs", token, map[string]any{
		"name": "Field Notes",
		"slug": "field-notes",
	})
	if decodeObject(t, status, raw, http.StatusForbidden)["error"] != "org_disabled" {
		t.Fatalf("orgs %d %s", status, raw)
	}
}

func TestOrganizationChoiceIssuesACode(t *testing.T) {
	ts := setupConfigured(t, func(cfg *config.Config) {
		cfg.Org.Enabled = true
	})
	base := ts.URL
	mgmt := managementAccessToken(t, base)
	user := createAPIUser(t, base, mgmt, "ada", "ada@example.com", true)
	notes := apiObject(t, http.MethodPost, base+"/api/orgs", mgmt, map[string]any{
		"name":     "Field Notes",
		"slug":     "field-notes",
		"logo_url": "https://cdn.example/notes.png",
	}, http.StatusCreated)
	archive := apiObject(t, http.MethodPost, base+"/api/orgs", mgmt, map[string]any{
		"name": "Archive",
		"slug": "archive",
	}, http.StatusCreated)
	notesID, _ := notes["id"].(string)
	archiveID, _ := archive["id"].(string)
	if notes["logo_url"] != "https://cdn.example/notes.png" || notesID == "" || archiveID == "" {
		t.Fatalf("create %v %v", notes, archive)
	}
	withDomain := apiObject(t, http.MethodPost, base+"/api/orgs/"+notesID+"/domains", mgmt, map[string]any{"domain": "notes.example"})
	domains, _ := withDomain["domains"].([]any)
	if len(domains) != 1 || domains[0] != "notes.example" {
		t.Fatalf("domain %v", withDomain)
	}
	userID := user["id"].(string)
	for _, orgID := range []string{notesID, archiveID} {
		added := apiObject(t, http.MethodPost, base+"/api/orgs/"+orgID+"/members", mgmt, map[string]any{
			"user_id": userID,
			"role":    "member",
		}, http.StatusCreated)
		if added["user_id"] != userID {
			t.Fatalf("member %v", added)
		}
	}
	if apiObject(t, http.MethodGet, base+"/api/orgs/"+notesID, mgmt, nil)["slug"] != "field-notes" {
		t.Fatal("get org")
	}
	if len(apiList(t, http.MethodGet, base+"/api/orgs", mgmt, nil)) < 2 {
		t.Fatal("list orgs")
	}

	client := createAPIClient(t, base, mgmt, map[string]any{
		"name":                       "Notes",
		"redirect_uris":              []string{"https://app.example/cb"},
		"grant_types":                []string{"authorization_code"},
		"scopes":                     []string{"openid"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	code := authorizeWithOrg(t, base, client["id"].(string), "field-notes")
	if code == "" {
		t.Fatal("missing code")
	}
}

func authorizeWithOrg(t *testing.T, base, clientID, slug string) string {
	t.Helper()
	browser := browserClient()
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
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", "https://app.example/cb")
	query.Set("scope", "openid")
	query.Set("state", "org-state")
	authResp, err := browser.Get(base + "/oauth/authorize?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	_ = authResp.Body.Close()
	orgURL := authResp.Header.Get("Location")
	if authResp.StatusCode != http.StatusFound || !strings.Contains(orgURL, "/organization") {
		t.Fatalf("authorize %d %s", authResp.StatusCode, orgURL)
	}
	if strings.HasPrefix(orgURL, "/") {
		orgURL = base + orgURL
	}
	page, err := browser.Get(orgURL)
	if err != nil {
		t.Fatal(err)
	}
	pageBody := readBody(t, page)
	if !strings.Contains(pageBody, "Field Notes") || !strings.Contains(pageBody, "Archive") {
		t.Fatalf("picker %s", pageBody)
	}
	form := url.Values{}
	form.Set("csrf_token", csrfFromBody(t, pageBody))
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "https://app.example/cb")
	form.Set("response_type", "code")
	form.Set("scope", "openid")
	form.Set("state", "org-state")
	form.Set("organization", slug)
	chosen, err := browser.PostForm(base+"/organization", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = chosen.Body.Close()
	next := chosen.Header.Get("Location")
	if chosen.StatusCode != http.StatusFound || !strings.Contains(next, "organization=") {
		t.Fatalf("choose %d %s", chosen.StatusCode, next)
	}
	if strings.HasPrefix(next, "/") {
		next = base + next
	}
	consentResp, err := browser.Get(next)
	if err != nil {
		t.Fatal(err)
	}
	consentLoc := consentResp.Header.Get("Location")
	_ = consentResp.Body.Close()
	if consentResp.StatusCode != http.StatusFound || !strings.Contains(consentLoc, "/consent") {
		t.Fatalf("after org %d %s", consentResp.StatusCode, consentLoc)
	}
	if strings.HasPrefix(consentLoc, "/") {
		consentLoc = base + consentLoc
	}
	consentPage, err := browser.Get(consentLoc)
	if err != nil {
		t.Fatal(err)
	}
	consentBody := readBody(t, consentPage)
	approve := url.Values{}
	approve.Set("csrf_token", csrfFromBody(t, consentBody))
	approve.Set("action", "approve")
	approve.Set("client_id", clientID)
	approve.Set("redirect_uri", "https://app.example/cb")
	approve.Set("response_type", "code")
	approve.Set("scope", "openid")
	approve.Set("state", "org-state")
	approve.Set("organization", slug)
	approved, err := browser.PostForm(base+"/consent", approve)
	if err != nil {
		t.Fatal(err)
	}
	_ = approved.Body.Close()
	again := approved.Header.Get("Location")
	if strings.HasPrefix(again, "/") {
		again = base + again
	}
	issued, err := browser.Get(again)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(issued.Body)
	_ = issued.Body.Close()
	loc := issued.Header.Get("Location")
	if issued.StatusCode != http.StatusFound {
		t.Fatalf("code %d %s %s", issued.StatusCode, loc, raw)
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("code")
}
