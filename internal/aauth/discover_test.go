package aauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/internal/server"
	"github.com/bravo68web/oauth-impl/internal/testpg"
)

func TestDiscoveryStaysOff(t *testing.T) {
	ts := testServer(t, config.DefaultConfig(), testpg.Open(t))
	resp, err := http.Get(ts.URL + "/.well-known/aauth-person.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestDiscoveryWhenEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AAuth.Enabled = true
	cfg.AAuth.ASIssuer = "http://issuer.example/as"
	ts := testServer(t, cfg, testpg.Open(t))

	person := getJSON(t, ts.URL+"/.well-known/aauth-person.json")
	if person["issuer"] != "http://localhost:8080" {
		t.Fatalf("person issuer %v", person["issuer"])
	}
	if person["person_token_endpoint"] != "http://localhost:8080/aauth/person-token" || person["auth_token_endpoint"] != "http://localhost:8080/aauth/auth-token" {
		t.Fatalf("person endpoints %v", person)
	}
	agent := getJSON(t, ts.URL+"/.well-known/aauth-agent.json")
	if agent["jwks_uri"] != "http://localhost:8080/aauth/jwks" {
		t.Fatalf("agent jwks %v", agent["jwks_uri"])
	}
	resource := getJSON(t, ts.URL+"/.well-known/aauth-resource.json")
	if resource["authorization_endpoint"] != "http://localhost:8080/aauth/authorize" {
		t.Fatalf("resource %v", resource)
	}

	access := getJSON(t, ts.URL+"/as/.well-known/aauth-access.json")
	if access["issuer"] != "http://issuer.example/as" || access["jwks_uri"] != "http://issuer.example/as/aauth/jwks" {
		t.Fatalf("access %v", access)
	}
	origin := jwksKid(t, ts.URL+"/aauth/jwks")
	if origin == "" || origin != jwksKid(t, ts.URL+"/as/aauth/jwks") {
		t.Fatal("jwks kid mismatch")
	}
}

func TestEd25519KeySurvivesRestart(t *testing.T) {
	db, dsn := testpg.OpenDSN(t)
	cfg := config.DefaultConfig()
	cfg.AAuth.Enabled = true
	first := testServer(t, cfg, db)
	kid := jwksKid(t, first.URL+"/aauth/jwks")
	second := testServer(t, cfg, testpg.Connect(t, dsn))
	if got := jwksKid(t, second.URL+"/aauth/jwks"); got != kid {
		t.Fatalf("kid %s then %s", kid, got)
	}
}

func TestAAuthRejectsBadMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AAuth.Enabled = true
	cfg.AAuth.ResourceMode = "nope"
	cfg.Normalize()
	if err := config.ValidateAAuth(cfg); err == nil {
		t.Fatal("expected resource_mode to fail")
	}
}

func testServer(t *testing.T, cfg *config.Config, db *database.DB) *httptest.Server {
	t.Helper()
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(1))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.GetRouter())
	t.Cleanup(ts.Close)
	return ts
}

func getJSON(t *testing.T, rawURL string) map[string]any {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %d %s", rawURL, resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func jwksKid(t *testing.T, rawURL string) string {
	t.Helper()
	body := getJSON(t, rawURL)
	keys, _ := body["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("keys %v", body["keys"])
	}
	key, _ := keys[0].(map[string]any)
	if key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["x"] == "" {
		t.Fatalf("jwk %v", key)
	}
	kid, _ := key["kid"].(string)
	return kid
}
