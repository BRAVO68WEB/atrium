package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bravo68web/atrium/internal/telemetry"
)

const maxBody = 1 << 20

// Profile is the identity returned by an upstream provider.
type Profile struct {
	Subject       string
	Email         string
	EmailVerified bool
	Username      string
	GivenName     string
	FamilyName    string
}

type tokenResult struct {
	AccessToken string
	IDToken     string
}

// Client talks to upstream OAuth providers. Discovery documents are cached for the process.
type Client struct {
	HTTP *http.Client
	mu   sync.Mutex
	docs map[string]discovery
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NewClient returns a client that times out at 10 seconds and does not follow redirects.
func NewClient(httpClient *http.Client) *Client {
	defer telemetry.Step("social.NewClient")()
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{HTTP: httpClient, docs: map[string]discovery{}}
}

// Prepare fills discovery endpoints onto p.
func (c *Client) Prepare(ctx context.Context, p Resolved) (Resolved, error) {
	defer telemetry.Step("social.Client.Prepare")()
	if !p.Discover {
		return p, nil
	}
	doc, err := c.discovery(ctx, p.Issuer)
	if err != nil {
		return Resolved{}, err
	}
	if p.Authorization == "" {
		p.Authorization = doc.AuthorizationEndpoint
	}
	if p.Token == "" {
		p.Token = doc.TokenEndpoint
	}
	if p.Userinfo == "" {
		p.Userinfo = doc.UserinfoEndpoint
	}
	if doc.Issuer != "" {
		p.Issuer = strings.TrimRight(doc.Issuer, "/")
	}
	p.jwks = doc.JWKSURI
	return p, nil
}

// Exchange trades an authorization code for tokens. Upstream tokens are not stored by the caller.
func (c *Client) Exchange(ctx context.Context, p Resolved, redirectURI, code, verifier string) (tokenResult, error) {
	defer telemetry.Step("social.Client.Exchange")()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.ClientID)
	form.Set("client_secret", p.ClientSecret)
	if p.UsePKCE && verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "atrium")
	res, err := c.do(req)
	if err != nil {
		return tokenResult{}, err
	}
	var body struct {
		AccessToken      string `json:"access_token"`
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(res, &body); err != nil {
		return tokenResult{}, fmt.Errorf("token response: %w", err)
	}
	if body.Error != "" || body.AccessToken == "" && body.IDToken == "" {
		return tokenResult{}, fmt.Errorf("token endpoint rejected the code")
	}
	return tokenResult{AccessToken: body.AccessToken, IDToken: body.IDToken}, nil
}

// Profile loads the upstream account. ID tokens are verified when the provider uses them.
func (c *Client) Profile(ctx context.Context, p Resolved, redirectURI string, tok tokenResult, nonce string) (Profile, error) {
	defer telemetry.Step("social.Client.Profile")()
	claims := map[string]any{}
	if p.UseIDToken {
		if tok.IDToken == "" {
			return Profile{}, fmt.Errorf("identity provider did not return an id token")
		}
		parsed, err := verifyIDToken(ctx, c, p.jwks, tok.IDToken, p.Issuer, p.ClientID, nonce)
		if err != nil {
			return Profile{}, err
		}
		claims = parsed
	}
	if tok.AccessToken != "" && (p.Userinfo != "" && (!p.UseIDToken || stringClaim(claims, p.EmailField) == "")) {
		info, err := c.userinfo(ctx, p.Userinfo, tok.AccessToken)
		if err != nil {
			return Profile{}, err
		}
		for k, v := range info {
			if _, ok := claims[k]; !ok {
				claims[k] = v
			}
		}
	}
	if p.Type == "github" && stringClaim(claims, p.EmailField) == "" && p.Emails != "" && tok.AccessToken != "" {
		email, verified := c.githubEmail(ctx, p.Emails, tok.AccessToken)
		if email != "" {
			claims[p.EmailField] = email
			if verified {
				claims["email_verified"] = true
			}
		}
	}
	subject := stringClaim(claims, p.SubjectField)
	if subject == "" {
		subject = stringClaim(claims, "sub")
	}
	if subject == "" {
		subject = stringClaim(claims, "id")
	}
	if subject == "" {
		return Profile{}, fmt.Errorf("identity provider did not return a subject")
	}
	email := stringClaim(claims, p.EmailField)
	given := stringClaim(claims, "given_name")
	family := stringClaim(claims, "family_name")
	if given == "" && family == "" {
		given, family = splitName(stringClaim(claims, "name"))
	}
	verified := false
	if p.EmailVerifiedField != "" {
		verified = boolClaim(claims, p.EmailVerifiedField)
	}
	if p.Type == "github" && boolClaim(claims, "email_verified") {
		verified = true
	}
	if p.Type == "facebook" {
		verified = false
	}
	return Profile{
		Subject:       subject,
		Email:         email,
		EmailVerified: verified && email != "",
		Username:      stringClaim(claims, p.UsernameField),
		GivenName:     given,
		FamilyName:    family,
	}, nil
}

func (c *Client) discovery(ctx context.Context, issuer string) (discovery, error) {
	defer telemetry.Step("social.Client.discovery")()
	issuer = strings.TrimRight(issuer, "/")
	c.mu.Lock()
	if doc, ok := c.docs[issuer]; ok {
		c.mu.Unlock()
		return doc, nil
	}
	c.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return discovery{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "atrium")
	raw, err := c.do(req)
	if err != nil {
		return discovery{}, err
	}
	var doc discovery
	if err := json.Unmarshal(raw, &doc); err != nil {
		return discovery{}, fmt.Errorf("discovery: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return discovery{}, fmt.Errorf("discovery document is missing endpoints")
	}
	c.mu.Lock()
	c.docs[issuer] = doc
	c.mu.Unlock()
	return doc, nil
}

func (c *Client) userinfo(ctx context.Context, endpoint, accessToken string) (map[string]any, error) {
	defer telemetry.Step("social.Client.userinfo")()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "atrium")
	raw, err := c.do(req)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	return out, nil
}

func (c *Client) githubEmail(ctx context.Context, endpoint, accessToken string) (string, bool) {
	defer telemetry.Step("social.Client.githubEmail")()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "atrium")
	raw, err := c.do(req)
	if err != nil {
		return "", false
	}
	var rows []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return "", false
	}
	var fallback string
	for _, row := range rows {
		if row.Verified && row.Primary {
			return row.Email, true
		}
		if row.Verified && fallback == "" {
			fallback = row.Email
		}
	}
	return fallback, fallback != ""
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	defer telemetry.Step("social.Client.do")()
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("upstream response is too large")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned %d", res.StatusCode)
	}
	return body, nil
}

func stringClaim(claims map[string]any, field string) string {
	defer telemetry.Step("social.stringClaim")()
	if field == "" || claims == nil {
		return ""
	}
	switch v := claims[field].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		return ""
	}
}

func boolClaim(claims map[string]any, field string) bool {
	defer telemetry.Step("social.boolClaim")()
	v, ok := claims[field]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func splitName(name string) (string, string) {
	defer telemetry.Step("social.splitName")()
	parts := strings.Fields(strings.TrimSpace(name))
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}
