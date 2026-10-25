package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/queue"
	"github.com/bravo68web/atrium/internal/server"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTAudienceFollowsResource(t *testing.T) {
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	cfg.Security.AccessTokenFormat = "jwt"
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1", "::1"}
	cfg.Management.ClientID = "test-mgmt"
	cfg.Management.ClientSecret = "test-mgmt-secret"
	srv, err := server.New(cfg, db, queue.NewMemoryQueue(10))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.GetRouter())
	defer ts.Close()

	client := registerClient(t, ts.URL, `{"client_name":"API","redirect_uris":["https://api.example/cb"],"grant_types":["client_credentials"],"scope":"openid","token_endpoint_auth_method":"client_secret_basic"}`)
	resource := "https://api.example/finance"
	withResource := clientCredentials(t, ts.URL, client, "grant_type=client_credentials&scope=openid&resource="+url.QueryEscape(resource))
	claims := decodeAccessClaims(t, withResource)
	if claims["aud"] != resource || claims["sub"] != client.ID || claims["azp"] != client.ID {
		t.Fatalf("resource token %v", claims)
	}
	if _, ok := claims["act"]; ok {
		t.Fatalf("act %v", claims["act"])
	}

	plain := clientCredentials(t, ts.URL, client, "grant_type=client_credentials&scope=openid")
	issuerClaims := decodeAccessClaims(t, plain)
	if issuerClaims["aud"] != config.DefaultConfig().Security.Issuer || issuerClaims["sub"] != client.ID {
		t.Fatalf("issuer token %v", issuerClaims)
	}
}

func clientCredentials(t *testing.T, base string, client registeredClient, form string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/oauth/token", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(client.ID, client.Secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	token, _ := body["access_token"].(string)
	if resp.StatusCode != http.StatusOK || strings.Count(token, ".") != 2 {
		t.Fatalf("token %d %s", resp.StatusCode, raw)
	}
	return token
}

func decodeAccessClaims(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, claims)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header["typ"] != "at+jwt" {
		t.Fatalf("typ %v", parsed.Header["typ"])
	}
	return claims
}
