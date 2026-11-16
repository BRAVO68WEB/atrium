package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
)

func TestRoleScopesReachTheToken(t *testing.T) {
	ts := setupConfigured(t, func(cfg *config.Config) {
		cfg.Org.Enabled = true
	})
	base := ts.URL
	mgmt := managementToken(t, base)
	resource := "https://api.envsync.cloud"
	apiObject(t, http.MethodPost, base+"/api/resources", mgmt, map[string]any{
		"uri": resource, "name": "EnvSync",
		"scopes": []string{"projects:read", "billing:read", "audit:read"},
	}, http.StatusCreated)
	viewer := apiObject(t, http.MethodPost, base+"/api/roles", mgmt, map[string]any{
		"name": "viewer", "description": "Read projects",
	}, http.StatusCreated)
	accountant := apiObject(t, http.MethodPost, base+"/api/roles", mgmt, map[string]any{
		"name": "accountant",
	}, http.StatusCreated)
	apiObject(t, http.MethodPut, base+"/api/roles/"+viewer["id"].(string)+"/scopes", mgmt, map[string]any{
		"scopes": []map[string]string{{"resource": resource, "scope": "projects:read"}},
	}, http.StatusOK)
	apiObject(t, http.MethodPut, base+"/api/roles/"+accountant["id"].(string)+"/scopes", mgmt, map[string]any{
		"scopes": []map[string]string{{"resource": resource, "scope": "billing:read"}},
	}, http.StatusOK)

	user := apiObject(t, http.MethodPost, base+"/api/users", mgmt, map[string]any{
		"username": "ada", "password": "correct horse", "email": "ada@example.com",
	}, http.StatusCreated)
	org := apiObject(t, http.MethodPost, base+"/api/orgs", mgmt, map[string]any{
		"name": "Acme", "slug": "acme-corp",
	}, http.StatusCreated)
	apiObject(t, http.MethodPost, base+"/api/orgs/"+org["id"].(string)+"/members", mgmt, map[string]any{
		"user_id": user["id"], "role": "member",
	}, http.StatusCreated)
	apiObject(t, http.MethodPost, base+"/api/users/"+user["id"].(string)+"/roles", mgmt, map[string]any{
		"role_id": viewer["id"],
	}, http.StatusCreated)
	apiObject(t, http.MethodPost, base+"/api/users/"+user["id"].(string)+"/roles", mgmt, map[string]any{
		"role_id": accountant["id"], "org_id": org["id"],
	}, http.StatusCreated)
	access := apiObject(t, http.MethodGet, base+"/api/users/"+user["id"].(string)+"/access", mgmt, nil, http.StatusOK)
	roles, _ := access["roles"].([]any)
	if len(roles) != 2 {
		t.Fatalf("access %v", access)
	}

	client := createAPIClient(t, base, mgmt, map[string]any{
		"name":                       "Notes",
		"redirect_uris":              []string{"https://app.example/cb"},
		"grant_types":                []string{"password"},
		"scopes":                     []string{"openid", "projects:read", "billing:read", "audit:read"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	global := passwordScopes(t, base, client, "")
	if !global["openid"] || !global["projects:read"] || global["billing:read"] || global["audit:read"] {
		t.Fatalf("global scopes %v", global)
	}
	orgScopes := passwordScopes(t, base, client, "acme-corp")
	if !orgScopes["openid"] || !orgScopes["projects:read"] || !orgScopes["billing:read"] || orgScopes["audit:read"] {
		t.Fatalf("org scopes %v", orgScopes)
	}
}

func passwordScopes(t *testing.T, base string, client map[string]any, organization string) map[string]bool {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"correct horse"},
		"scope":      {"openid projects:read billing:read audit:read"},
	}
	if organization != "" {
		form.Set("organization", organization)
	}
	status, body := postForm(t, base+"/oauth/token", client["id"].(string), client["secret"].(string), form)
	if status != http.StatusOK {
		t.Fatalf("grant %d %v", status, body)
	}
	got := map[string]bool{}
	for _, scope := range strings.Fields(body["scope"].(string)) {
		got[scope] = true
	}
	return got
}
