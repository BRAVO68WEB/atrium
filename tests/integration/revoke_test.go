package integration

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRevokeRejectsAnotherClientsToken(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	mgmt := managementToken(t, ts.URL)
	owner := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":          "Field Notes",
		"grant_types":   []string{"password"},
		"scopes":        []string{"openid", "email"},
		"redirect_uris": []string{"http://localhost:8080/field", "http://localhost:8080/other"},
	})
	other := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":        "Other App",
		"grant_types": []string{"password"},
		"scopes":      []string{"openid"},
	})
	user := createAPIUser(t, ts.URL, mgmt, "ada", "ada@fieldnotes.example", true)
	issued := passwordGrant(t, ts.URL, owner, user)
	access, _ := issued["access_token"].(string)
	refresh, _ := issued["refresh_token"].(string)

	status, body := postForm(t, ts.URL+"/oauth/revoke", other["id"].(string), other["secret"].(string), url.Values{
		"token": {access},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("cross-client revoke %d %v", status, body)
	}
	active := introspectAs(t, ts.URL, owner, access)
	if active["active"] != true {
		t.Fatalf("token was revoked by the other client: %v", active)
	}

	status, body = postForm(t, ts.URL+"/oauth/revoke", owner["id"].(string), owner["secret"].(string), url.Values{
		"token":           {refresh},
		"token_type_hint": {"access_token"},
	})
	if status != http.StatusOK {
		t.Fatalf("hint %d %v", status, body)
	}
	status, refreshed := postForm(t, ts.URL+"/oauth/token", owner["id"].(string), owner["secret"].(string), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if status != http.StatusBadRequest || refreshed["error"] != "invalid_grant" {
		t.Fatalf("refresh after hinted revoke %d %v", status, refreshed)
	}

	status, pushed := postForm(t, ts.URL+"/oauth/par", owner["id"].(string), owner["secret"].(string), url.Values{
		"response_type": {"code"},
		"client_id":     {owner["id"].(string)},
	})
	if status != http.StatusBadRequest || pushed["error"] != "invalid_request" {
		t.Fatalf("par %d %v", status, pushed)
	}
}
