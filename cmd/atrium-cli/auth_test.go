package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIRequestSetsBearer(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-1"})
			return
		}
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	serverURL = srv.URL
	mgmtClientID = "mgmt"
	mgmtClientSecret = "secret"
	mgmt.ClearToken()
	configPath = filepath.Join(t.TempDir(), "missing.yaml")

	resp, err := apiGet(srv.URL + "/api/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got != "Bearer tok-1" {
		t.Fatalf("authorization %q", got)
	}
}
