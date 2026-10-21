package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestSocialLoginCreatesAndRejectsAccounts(t *testing.T) {
	idp := startSocialIDP(t)

	created := setupBound(t, func(cfg *config.Config) {
		cfg.Social.Providers = []config.SocialProvider{socialProvider(idp.URL)}
	})
	missing, err := http.Get(created.URL + "/login/social/missing")
	if err != nil {
		t.Fatal(err)
	}
	_ = missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown provider %d", missing.StatusCode)
	}
	idp.Email = "ada-social@fieldnotes.example"
	idp.Username = "ada-social"
	idp.Subject = "social-subject-1"
	profile := finishSocialLogin(t, created.URL, idp)
	if profile.StatusCode != http.StatusOK || !strings.Contains(profile.Body, "ada-social") || !strings.Contains(profile.Body, "ada-social@fieldnotes.example") {
		t.Fatalf("profile %d %s", profile.StatusCode, profile.Body)
	}

	blocked := setupBound(t, func(cfg *config.Config) {
		cfg.Security.DisableSocialRegistration = true
		cfg.Social.Providers = []config.SocialProvider{socialProvider(idp.URL)}
	})
	idp.Email = "new-social@fieldnotes.example"
	idp.Username = "new-social"
	idp.Subject = "social-subject-2"
	denied := finishSocialLogin(t, blocked.URL, idp)
	if denied.StatusCode != http.StatusForbidden || !strings.Contains(denied.Body, "Social registration is disabled") {
		t.Fatalf("disabled %d %s", denied.StatusCode, denied.Body)
	}

	taken := setupBound(t, func(cfg *config.Config) {
		cfg.Social.Providers = []config.SocialProvider{socialProvider(idp.URL)}
	})
	mgmt := managementAccessToken(t, taken.URL)
	createAPIUser(t, taken.URL, mgmt, "ada", "ada@example.com", true)
	idp.Email = "ada@example.com"
	idp.Username = "ada-upstream"
	idp.Subject = "social-subject-3"
	conflict := finishSocialLogin(t, taken.URL, idp)
	if conflict.StatusCode != http.StatusOK || !strings.Contains(conflict.Body, "already exists") {
		t.Fatalf("email in use %d %s", conflict.StatusCode, htmlSnippet(conflict.Body, "error"))
	}
}

func socialProvider(issuer string) config.SocialProvider {
	return config.SocialProvider{
		ID:           "local",
		Type:         "oidc",
		Name:         "Local",
		Enabled:      true,
		ClientID:     "notes-social",
		ClientSecret: "notes-social-secret",
		Issuer:       issuer,
	}
}

type socialPage struct {
	StatusCode int
	Body       string
	Location   string
}

type socialIDP struct {
	URL      string
	Email    string
	Username string
	Subject  string
}

func startSocialIDP(t *testing.T) *socialIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &socialIDP{}
	var codes sync.Map
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	idp.URL = srv.URL
	jwk := map[string]string{
		"kty": "RSA",
		"kid": "social-1",
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeSocialJSON(w, map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeSocialJSON(w, map[string]any{"keys": []map[string]string{jwk}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		code := uuid.NewString()
		codes.Store(code, r.URL.Query().Get("nonce"))
		back, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect", http.StatusBadRequest)
			return
		}
		q := back.Query()
		q.Set("code", code)
		q.Set("state", r.URL.Query().Get("state"))
		back.RawQuery = q.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		nonce, _ := codes.Load(r.Form.Get("code"))
		nonceText, _ := nonce.(string)
		claims := jwt.MapClaims{
			"iss":                srv.URL,
			"sub":                idp.Subject,
			"aud":                r.Form.Get("client_id"),
			"exp":                time.Now().Add(5 * time.Minute).Unix(),
			"iat":                time.Now().Unix(),
			"nonce":              nonceText,
			"email":              idp.Email,
			"email_verified":     true,
			"preferred_username": idp.Username,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "social-1"
		signed, err := token.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeSocialJSON(w, map[string]string{
			"access_token": "upstream-access",
			"id_token":     signed,
			"token_type":   "Bearer",
		})
	})
	return idp
}

func finishSocialLogin(t *testing.T, base string, idp *socialIDP) socialPage {
	t.Helper()
	browser := browserClient()
	start, err := browser.Get(base + "/login/social/local?next=/profile")
	if err != nil {
		t.Fatal(err)
	}
	startBody := readBody(t, start)
	if start.StatusCode != http.StatusFound {
		t.Fatalf("start %d %s", start.StatusCode, startBody)
	}
	upstream, err := browser.Get(start.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = upstream.Body.Close()
	if upstream.StatusCode != http.StatusFound {
		t.Fatalf("idp %d", upstream.StatusCode)
	}
	callback, err := browser.Get(upstream.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, callback)
	if callback.StatusCode == http.StatusFound && strings.HasPrefix(callback.Header.Get("Location"), "/") {
		page, err := browser.Get(base + callback.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		return socialPage{StatusCode: page.StatusCode, Body: readBody(t, page), Location: callback.Header.Get("Location")}
	}
	return socialPage{StatusCode: callback.StatusCode, Body: body, Location: callback.Header.Get("Location")}
}

func htmlSnippet(body, needle string) string {
	i := strings.Index(body, needle)
	if i < 0 {
		if len(body) > 240 {
			return body[:240]
		}
		return body
	}
	start := i - 80
	if start < 0 {
		start = 0
	}
	end := i + 180
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

func writeSocialJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
