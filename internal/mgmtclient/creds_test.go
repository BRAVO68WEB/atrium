package mgmtclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveReadsCLIFileThenManagementFile(t *testing.T) {
	t.Setenv("OAUTH_CLI_SERVER", "")
	t.Setenv("OAUTH_CLI_CLIENT_ID", "")
	t.Setenv("OAUTH_CLI_CLIENT_SECRET", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")
	if err := os.WriteFile(path, []byte("server: https://auth.example\nclient_id: from-cli\nclient_secret: cli-secret\nmanagement:\n  client_id: from-server\n  client_secret: server-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &Client{ConfigPath: path, ServerURL: defaultServerURL}
	if err := client.Resolve(false); err != nil {
		t.Fatal(err)
	}
	if client.ServerURL != "https://auth.example" || client.ClientID != "from-cli" || client.ClientSecret != "cli-secret" {
		t.Fatalf("cli file %+v", client)
	}

	serverFile := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(serverFile, []byte("management:\n  client_id: mgmt\n  client_secret: mgmt-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client = &Client{ConfigPath: serverFile, ServerURL: defaultServerURL}
	if err := client.Resolve(false); err != nil {
		t.Fatal(err)
	}
	if client.ClientID != "mgmt" || client.ClientSecret != "mgmt-secret" || client.ServerURL != defaultServerURL {
		t.Fatalf("management file %+v", client)
	}
}

func TestResolveEnvironmentOverridesTheFile(t *testing.T) {
	t.Setenv("OAUTH_CLI_SERVER", "https://env.example")
	t.Setenv("OAUTH_CLI_CLIENT_ID", "env-id")
	t.Setenv("OAUTH_CLI_CLIENT_SECRET", "env-secret")
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")
	if err := os.WriteFile(path, []byte("server: https://file.example\nclient_id: file-id\nclient_secret: file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &Client{ConfigPath: path, ServerURL: defaultServerURL}
	if err := client.Resolve(false); err != nil {
		t.Fatal(err)
	}
	if client.ServerURL != "https://env.example" || client.ClientID != "env-id" || client.ClientSecret != "env-secret" {
		t.Fatalf("env %+v", client)
	}
	explicit := &Client{ConfigPath: path, ServerURL: "https://flag.example", ClientID: "flag", ClientSecret: "flag-secret"}
	if err := explicit.Resolve(true); err != nil {
		t.Fatal(err)
	}
	if explicit.ServerURL != "https://flag.example" || explicit.ClientID != "flag" {
		t.Fatalf("flags %+v", explicit)
	}
}
