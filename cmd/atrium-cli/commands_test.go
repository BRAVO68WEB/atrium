package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestManagementCommandsReachTheServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fakeManagementAPI))
	t.Cleanup(srv.Close)

	commands := [][]string{
		{"server", "status"},
		{"server", "discovery"},
		{"client", "list"},
		{"client", "create", "--name", "Field Notes", "--redirect-uri", "https://notes.example/cb"},
		{"client", "get", "app-1"},
		{"client", "update", "app-1", "--dcr-enabled"},
		{"client", "delete", "app-1"},
		{"client", "master"},
		{"user", "list"},
		{"user", "create", "--username", "ada", "--password", "correct-horse", "--email", "ada@fieldnotes.example"},
		{"user", "get", "user-1"},
		{"user", "password", "user-1", "--password", "correct-horse-2"},
		{"user", "disable", "user-1"},
		{"user", "enable", "user-1"},
		{"token", "list", "--client-id", "app-1"},
		{"token", "refresh", "list"},
		{"token", "refresh", "revoke", "refresh-1"},
		{"token", "introspect", "access-1"},
		{"token", "revoke", "access-1"},
		{"ciba", "pending"},
		{"ciba", "approve", "auth-1", "--user-id", "user-1"},
		{"ciba", "deny", "auth-1", "--reason", "no"},
		{"flow", "client-credentials", "--client-id", "app-1", "--client-secret", "secret"},
		{"flow", "device", "--client-id", "app-1", "--client-secret", "secret"},
		{"mfa", "enable", "--user-id", "user-1", "--show-secret"},
		{"mfa", "verify", "--user-id", "user-1", "--code", "123456"},
		{"mfa", "status", "--user-id", "user-1"},
		{"scope", "list"},
		{"scope", "create", "--name", "notes.read"},
		{"scope", "delete", "notes.read"},
		{"resource", "list"},
		{"resource", "create", "--uri", "https://api.example", "--name", "Notes"},
		{"resource", "delete", "https://api.example"},
		{"consent", "list", "--user-id", "user-1"},
		{"consent", "revoke", "--user-id", "user-1", "--client-id", "app-1"},
		{"webhook", "list"},
		{"webhook", "create", "--url", "https://hooks.example/in", "--event", "login"},
		{"webhook", "test", "hook-1"},
		{"webhook", "delete", "hook-1"},
		{"analytics", "logins"},
		{"audit", "list"},
		{"keys", "rotate"},
		{"keys", "generate", "--output", t.TempDir(), "--dpop-only"},
		{"org", "create", "--name", "Field Notes", "--slug", "field-notes", "--domain", "fieldnotes.example"},
		{"org", "domain", "--org", "field-notes", "--domain", "notes.example"},
		{"org", "member", "--org", "field-notes", "--user-id", "user-1"},
	}

	t.Cleanup(func() {
		serverURL = "http://127.0.0.1:8080"
		mgmtClientID = ""
		mgmtClientSecret = ""
		configPath = "config.yaml"
		mgmt.ClearToken()
	})

	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			serverURL = srv.URL
			mgmtClientID = "mgmt"
			mgmtClientSecret = "secret"
			configPath = filepath.Join(t.TempDir(), "missing.yaml")
			mgmt.ClearToken()

			cmd := newRootCmd()
			cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
				serverURL = srv.URL
				mgmtClientID = "mgmt"
				mgmtClientSecret = "secret"
			}
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append([]string{"--server", srv.URL, "--client-id", "mgmt", "--client-secret", "secret"}, args...))
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func fakeManagementAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(path, "/oauth/token") {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-1",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "openid",
		})
		return
	}
	if strings.HasSuffix(path, "/oauth/device") {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "device-1",
			"user_code":        "ABCD-EFGH",
			"verification_uri": "https://notes.example/device",
			"expires_in":       600,
		})
		return
	}
	if strings.HasSuffix(path, "/health") {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "time": "now"})
		return
	}
	if strings.Contains(path, "openid-configuration") || strings.Contains(path, "/analytics/") || strings.HasSuffix(path, "/mfa/status") {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": "https://idp.example", "window": "720h", "attempts": 1,
			"successes": 1, "failures": 0, "failure_rate": 0, "unique_ips": 1, "new_ips": 0,
			"user_id": "user-1", "mfa_enabled": true,
			"by_ip": []any{map[string]any{"ip": "127.0.0.1", "attempts": 1, "successes": 1, "failures": 0, "new": false, "last_seen": "now"}},
		})
		return
	}
	switch r.Method {
	case http.MethodPost:
		if strings.Contains(path, "/ciba/") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		if strings.Contains(path, "/mfa/") || strings.Contains(path, "/password") || strings.Contains(path, "/revoke") ||
			strings.Contains(path, "/rotate") || strings.HasSuffix(path, "/test") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "secret": "totp-secret", "kids": []string{"kid-1"}})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "created-1", "secret": "secret-1", "name": "notes.read", "uri": "https://api.example"})
		return
	case http.MethodPut, http.MethodPatch:
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "app-1", "status": "ok"})
		return
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		return
	default:
		if managementList(path) {
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": "row-1", "name": "Field Notes", "username": "ada", "email": "ada@fieldnotes.example",
				"grant_types": []string{"authorization_code"}, "token_endpoint_auth_method": "client_secret_basic",
				"auth_req_id": "auth-req-0123456789abcdef", "client_id": "app-1", "binding_message": "Sign in",
				"status": "pending", "expires_at": "soon", "token": "access-token-value-long",
				"user_id": "user-1", "token_type": "Bearer", "family_id": "family-1",
				"enabled": true, "events": []string{"login"}, "url": "https://hooks.example/in",
				"action": "login", "actor_id": "user-1", "created_at": "now",
			}})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "app-1", "name": "Field Notes", "username": "ada", "email": "ada@fieldnotes.example",
			"dcr_enabled": false, "cimd_enabled": false,
		})
	}
}

func managementList(path string) bool {
	switch {
	case strings.HasSuffix(path, "/api/clients"),
		strings.HasSuffix(path, "/api/users"),
		strings.HasSuffix(path, "/api/scopes"),
		strings.HasSuffix(path, "/api/resources"),
		strings.HasSuffix(path, "/api/webhooks"),
		strings.Contains(path, "/api/consents"),
		strings.Contains(path, "/api/tokens"),
		strings.Contains(path, "/api/refresh-tokens"),
		strings.HasSuffix(path, "/api/audit"),
		strings.HasSuffix(path, "/ciba/pending"):
		return true
	default:
		return false
	}
}
