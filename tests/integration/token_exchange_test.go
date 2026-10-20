package integration

import (
	"net/http"
	"net/url"
	"testing"
)

func TestTokenExchangeStaysWithTheIssuingClient(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementToken(t, ts.URL)
	owner := createAPIClient(t, ts.URL, token, map[string]any{
		"name":        "Field Notes",
		"grant_types": []string{"password", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"scopes":      []string{"openid"},
	})
	other := createAPIClient(t, ts.URL, token, map[string]any{
		"name":        "Other App",
		"grant_types": []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		"scopes":      []string{"openid"},
	})
	user := createAPIUser(t, ts.URL, token, "ada", "ada@fieldnotes.example", true)
	issued := passwordGrant(t, ts.URL, owner, user)
	subject, _ := issued["access_token"].(string)

	status, stolen := postForm(t, ts.URL+"/oauth/token", other["id"].(string), other["secret"].(string), url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != http.StatusBadRequest || stolen["error"] != "invalid_grant" {
		t.Fatalf("stolen %d %v", status, stolen)
	}

	status, widened := postForm(t, ts.URL+"/oauth/token", owner["id"].(string), owner["secret"].(string), url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"admin"},
	})
	if status != http.StatusBadRequest || widened["error"] != "invalid_scope" {
		t.Fatalf("scope %d %v", status, widened)
	}

	status, again := postForm(t, ts.URL+"/oauth/token", owner["id"].(string), owner["secret"].(string), url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if status != http.StatusOK || again["scope"] != issued["scope"] || again["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("exchange %d %v issued %v", status, again, issued["scope"])
	}
}
