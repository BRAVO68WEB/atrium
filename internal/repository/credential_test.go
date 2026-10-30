package repository

import (
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func TestOpaqueTokensAreStoredAsHashes(t *testing.T) {
	db := testpg.Open(t)
	if _, err := db.Exec(`INSERT INTO clients (id, secret, name) VALUES ('app', 'secret', 'App')`); err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenRepository(db)
	access := &models.AccessToken{
		Token: "access-token-1", ClientID: "app", UserID: "user-1",
		Scopes: []string{"openid"}, TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := tokens.SaveAccessToken(access); err != nil {
		t.Fatal(err)
	}
	refresh := &models.RefreshToken{
		Token: "refresh-token-1", AccessToken: "access-token-1", ClientID: "app", UserID: "user-1",
		Scopes: []string{"openid"}, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := tokens.SaveRefreshToken(refresh); err != nil {
		t.Fatal(err)
	}
	var storedAccess, storedRefresh, link string
	if err := db.QueryRow(`SELECT token FROM access_tokens WHERE client_id = 'app'`).Scan(&storedAccess); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT token, access_token FROM refresh_tokens WHERE client_id = 'app'`).Scan(&storedRefresh, &link); err != nil {
		t.Fatal(err)
	}
	if storedAccess == "access-token-1" || storedRefresh == "refresh-token-1" || link == "access-token-1" {
		t.Fatalf("raw bearer stored access=%s refresh=%s link=%s", storedAccess, storedRefresh, link)
	}
	if storedAccess != crypto.CredentialHash("access-token-1") || link != storedAccess {
		t.Fatalf("keys access=%s link=%s", storedAccess, link)
	}
	found, err := tokens.GetAccessToken("access-token-1")
	if err != nil || found.Token != "access-token-1" || found.ID == "" {
		t.Fatalf("get access %+v %v", found, err)
	}
	gotRefresh, err := tokens.GetRefreshToken("refresh-token-1")
	if err != nil || gotRefresh.Token != "refresh-token-1" {
		t.Fatalf("get refresh %+v %v", gotRefresh, err)
	}
}

func TestJWTAccessTokenStoresJTI(t *testing.T) {
	db := testpg.Open(t)
	if _, err := db.Exec(`INSERT INTO clients (id, secret, name) VALUES ('app', 'secret', 'App')`); err != nil {
		t.Fatal(err)
	}
	tokens := NewTokenRepository(db)
	tokens.SetAccessVerifier(func(raw string) (string, error) {
		if strings.HasSuffix(raw, ".bad") {
			return "", errToken
		}
		return "abc", nil
	})
	payload := "eyJqdGkiOiJhYmMifQ"
	jwt := "hdr." + payload + ".sig"
	access := &models.AccessToken{
		Token: jwt, ClientID: "app", UserID: "user-1",
		Scopes: []string{"openid"}, TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := tokens.SaveAccessToken(access); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow(`SELECT token FROM access_tokens WHERE client_id = 'app'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "jti:abc" || strings.Contains(stored, payload) {
		t.Fatalf("stored %s", stored)
	}
	if _, err := tokens.GetAccessToken("hdr." + payload + ".bad"); err == nil {
		t.Fatal("bad signature was accepted")
	}
	found, err := tokens.GetAccessToken(jwt)
	if err != nil || found.JTI != "abc" || found.Token != jwt {
		t.Fatalf("get jwt %+v %v", found, err)
	}
}

var errToken = errString("token")

type errString string

func (e errString) Error() string { return string(e) }

func TestClientSecretIsSealed(t *testing.T) {
	db := testpg.Open(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	clients := NewClientRepository(db)
	clients.SetKey(key)
	client := &models.Client{
		ID: "app", Secret: "client-secret", Name: "App",
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://app.example/cb"},
		GrantTypes:              []string{"authorization_code"},
		Scopes:                  []string{"openid"},
		CreatedAt:               time.Now(), UpdatedAt: time.Now(),
	}
	if err := clients.Create(client); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow(`SELECT secret FROM clients WHERE id = 'app'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "enc:v1:") || strings.Contains(stored, "client-secret") {
		t.Fatalf("stored %s", stored)
	}
	found, err := clients.GetByID("app")
	if err != nil || found.Secret != "client-secret" {
		t.Fatalf("read %+v %v", found, err)
	}
}
