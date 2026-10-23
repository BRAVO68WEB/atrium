package integration

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCIBAPollApproveAndDeny(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	mgmt := managementToken(t, ts.URL)
	user := createAPIUser(t, ts.URL, mgmt, "ada", "ada@example.com", true)
	client := createAPIClient(t, ts.URL, mgmt, map[string]any{
		"name":                       "TV",
		"redirect_uris":              []string{"https://tv.example/cb"},
		"grant_types":                []string{"urn:openid:params:grant-type:ciba"},
		"scopes":                     []string{"openid"},
		"token_endpoint_auth_method": "client_secret_basic",
	})

	approved := startCIBA(t, ts.URL, client, "ada", "Sign in on the television")
	pendingStatus, pendingBody := postForm(t, ts.URL+"/oauth/token", client["id"].(string), client["secret"].(string), url.Values{
		"grant_type":  {"urn:openid:params:grant-type:ciba"},
		"auth_req_id": {approved},
	})
	if pendingStatus != http.StatusBadRequest || pendingBody["error"] != "authorization_pending" {
		t.Fatalf("pending poll %d %v", pendingStatus, pendingBody)
	}

	listed := apiList(t, http.MethodGet, ts.URL+"/ciba/pending", mgmt, nil)
	found := false
	for _, item := range listed {
		row, _ := item.(map[string]any)
		if row["auth_req_id"] == approved {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending %v", listed)
	}
	status := apiObject(t, http.MethodGet, ts.URL+"/ciba/status?auth_req_id="+url.QueryEscape(approved), mgmt, nil)
	if status["status"] != "pending" {
		t.Fatalf("status %v", status)
	}

	ok := apiObject(t, http.MethodPost, ts.URL+"/api/ciba/"+url.PathEscape(approved)+"/approve", mgmt, map[string]string{
		"user_id": user["id"].(string),
	})
	if ok["status"] != "approved" {
		t.Fatalf("approve %v", ok)
	}
	granted, grantBody := postForm(t, ts.URL+"/oauth/token", client["id"].(string), client["secret"].(string), url.Values{
		"grant_type":  {"urn:openid:params:grant-type:ciba"},
		"auth_req_id": {approved},
	})
	if granted != http.StatusOK || grantBody["access_token"] == "" {
		t.Fatalf("approved poll %d %v", granted, grantBody)
	}

	denied := startCIBA(t, ts.URL, client, "ada", "Deny this one")
	no := apiObject(t, http.MethodPost, ts.URL+"/ciba/deny?auth_req_id="+url.QueryEscape(denied)+"&reason="+url.QueryEscape("no thanks"), mgmt, nil)
	if no["status"] != "denied" {
		t.Fatalf("deny %v", no)
	}
	blocked, blockedBody := postForm(t, ts.URL+"/oauth/token", client["id"].(string), client["secret"].(string), url.Values{
		"grant_type":  {"urn:openid:params:grant-type:ciba"},
		"auth_req_id": {denied},
	})
	if blocked != http.StatusBadRequest || blockedBody["error"] != "access_denied" {
		t.Fatalf("denied poll %d %v", blocked, blockedBody)
	}
}

func startCIBA(t *testing.T, base string, client map[string]any, loginHint, binding string) string {
	t.Helper()
	status, body := postForm(t, base+"/oauth/bc-authorize", client["id"].(string), client["secret"].(string), url.Values{
		"login_hint":      {loginHint},
		"scope":           {"openid"},
		"binding_message": {binding},
	})
	if status != http.StatusOK {
		t.Fatalf("bc-authorize %d %v", status, body)
	}
	id, _ := body["auth_req_id"].(string)
	if id == "" || body["interval"] == nil {
		t.Fatalf("bc-authorize %v", body)
	}
	return id
}
