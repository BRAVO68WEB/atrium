package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestMobileCommandsReachTheServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-1"})
			return
		}
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "time": "now"})
			return
		}
		if r.URL.Path == "/ciba/pending" {
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"auth_req_id":     "auth-req-0123456789abcdef",
				"client_id":       "app-1",
				"binding_message": "Sign in",
				"status":          "pending",
				"expires_at":      "soon",
			}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	t.Cleanup(srv.Close)

	for _, args := range [][]string{
		{"list"},
		{"approve", "auth-1", "--user-id", "user-1"},
		{"deny", "auth-1"},
		{"status"},
	} {
		serverURL = srv.URL
		mgmtClientID = "mgmt"
		mgmtClientSecret = "secret"
		configPath = filepath.Join(t.TempDir(), "missing.yaml")
		mgmt.ClearToken()
		cmd := newRootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"--server", srv.URL, "--client-id", "mgmt", "--client-secret", "secret"}, args...))
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
