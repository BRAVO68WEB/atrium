package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/pkg/passhash"
	"golang.org/x/crypto/bcrypt"
)

func TestUserImportRoundTrip(t *testing.T) {
	ts, cleanup := setupTestServer(t)
	defer cleanup()
	token := managementToken(t, ts.URL)
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), passhash.DefaultBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"mode": "create",
		"users": []map[string]any{{
			"username":       "ada",
			"email":          "ada@example.com",
			"email_verified": true,
			"password_hash":  string(hash),
		}},
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/users/import", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var imported map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&imported); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || imported["created"] != float64(1) {
		t.Fatalf("import %d %v", resp.StatusCode, imported)
	}
	client := createAPIClient(t, ts.URL, token, map[string]any{
		"name":        "Password",
		"grant_types": []string{"password"},
		"scopes":      []string{"openid"},
	})
	status, issued := postForm(t, ts.URL+"/oauth/token", client["id"].(string), client["secret"].(string), mapForm(map[string]string{
		"grant_type": "password",
		"username":   "ada",
		"password":   "correct horse",
		"scope":      "openid",
	}))
	if status != 200 {
		t.Fatalf("login %d %v", status, issued)
	}
	exportReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/users/export", nil)
	exportReq.Header.Set("Authorization", "Bearer "+token)
	exportResp, err := http.DefaultClient.Do(exportReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exportResp.Body.Close() }()
	var exported map[string]any
	if err := json.NewDecoder(exportResp.Body).Decode(&exported); err != nil {
		t.Fatal(err)
	}
	users, _ := exported["users"].([]any)
	row, _ := users[0].(map[string]any)
	if row["password_hash"] != nil && row["password_hash"] != "" {
		t.Fatalf("export leaked a hash: %v", row["password_hash"])
	}
	secretReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/users/export?include_secrets=true", nil)
	secretReq.Header.Set("Authorization", "Bearer "+token)
	secretResp, err := http.DefaultClient.Do(secretReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secretResp.Body.Close() }()
	var secrets map[string]any
	if err := json.NewDecoder(secretResp.Body).Decode(&secrets); err != nil {
		t.Fatal(err)
	}
	secretUsers, _ := secrets["users"].([]any)
	secretRow, _ := secretUsers[0].(map[string]any)
	stored, _ := secretRow["password_hash"].(string)
	if !strings.HasPrefix(stored, "$2") {
		t.Fatalf("secret export %v", secretRow)
	}
}

func mapForm(values map[string]string) map[string][]string {
	form := map[string][]string{}
	for key, value := range values {
		form[key] = []string{value}
	}
	return form
}
