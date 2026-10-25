package social

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// Resolved is a provider with preset endpoints filled in.
type Resolved struct {
	ID                 string
	Type               string
	Name               string
	ClientID           string
	ClientSecret       string
	Scopes             []string
	Issuer             string
	Authorization      string
	Token              string
	Userinfo           string
	Emails             string
	SubjectField       string
	EmailField         string
	UsernameField      string
	EmailVerifiedField string
	UsePKCE            bool
	UseIDToken         bool
	Discover           bool
	ScopeSep           string
	jwks               string
}

// Resolve applies a preset. Discovery URLs are filled later by the HTTP client.
func Resolve(p config.SocialProvider) (Resolved, error) {
	defer telemetry.Step("social.Resolve")()
	r := Resolved{
		ID:                 p.ID,
		Type:               p.Type,
		Name:               p.Name,
		ClientID:           p.ClientID,
		ClientSecret:       p.ClientSecret,
		Scopes:             append([]string{}, p.Scopes...),
		Issuer:             strings.TrimRight(p.Issuer, "/"),
		Authorization:      p.AuthorizationEndpoint,
		Token:              p.TokenEndpoint,
		Userinfo:           p.UserinfoEndpoint,
		SubjectField:       p.SubjectField,
		EmailField:         p.EmailField,
		UsernameField:      p.UsernameField,
		EmailVerifiedField: p.EmailVerifiedField,
		UsePKCE:            true,
		ScopeSep:           " ",
	}
	if r.Name == "" {
		r.Name = defaultName(p.Type, p.ID)
	}
	switch p.Type {
	case "google":
		if r.Issuer == "" {
			r.Issuer = "https://accounts.google.com"
		}
		r.Discover = true
		r.UseIDToken = true
		if len(r.Scopes) == 0 {
			r.Scopes = []string{"openid", "email", "profile"}
		}
		if r.SubjectField == "" {
			r.SubjectField = "sub"
		}
		if r.EmailField == "" {
			r.EmailField = "email"
		}
		if r.EmailVerifiedField == "" {
			r.EmailVerifiedField = "email_verified"
		}
	case "github":
		if r.Authorization == "" {
			r.Authorization = "https://github.com/login/oauth/authorize"
		}
		if r.Token == "" {
			r.Token = "https://github.com/login/oauth/access_token"
		}
		if r.Userinfo == "" {
			r.Userinfo = "https://api.github.com/user"
		}
		r.Emails = strings.TrimRight(r.Userinfo, "/") + "/emails"
		if len(r.Scopes) == 0 {
			r.Scopes = []string{"read:user", "user:email"}
		}
		if r.SubjectField == "" {
			r.SubjectField = "id"
		}
		if r.EmailField == "" {
			r.EmailField = "email"
		}
		if r.UsernameField == "" {
			r.UsernameField = "login"
		}
	case "facebook":
		if r.Authorization == "" {
			r.Authorization = "https://www.facebook.com/v19.0/dialog/oauth"
		}
		if r.Token == "" {
			r.Token = "https://graph.facebook.com/v19.0/oauth/access_token"
		}
		if r.Userinfo == "" {
			r.Userinfo = "https://graph.facebook.com/v19.0/me?fields=id,name,email"
		}
		if len(r.Scopes) == 0 {
			r.Scopes = []string{"email", "public_profile"}
		}
		r.UsePKCE = false
		r.ScopeSep = ","
		if r.SubjectField == "" {
			r.SubjectField = "id"
		}
		if r.EmailField == "" {
			r.EmailField = "email"
		}
		if r.UsernameField == "" {
			r.UsernameField = "name"
		}
	case "oidc":
		r.Discover = true
		r.UseIDToken = true
		if len(r.Scopes) == 0 {
			r.Scopes = []string{"openid", "email", "profile"}
		}
		if r.SubjectField == "" {
			r.SubjectField = "sub"
		}
		if r.EmailField == "" {
			r.EmailField = "email"
		}
		if r.EmailVerifiedField == "" {
			r.EmailVerifiedField = "email_verified"
		}
		if r.UsernameField == "" {
			r.UsernameField = "preferred_username"
		}
	case "oauth2":
		if len(r.Scopes) == 0 {
			r.Scopes = []string{"openid", "email"}
		}
		if r.SubjectField == "" {
			r.SubjectField = "sub"
		}
		if r.EmailField == "" {
			r.EmailField = "email"
		}
		if r.UsernameField == "" {
			r.UsernameField = "preferred_username"
		}
		if r.EmailVerifiedField == "" {
			r.EmailVerifiedField = "email_verified"
		}
	default:
		return Resolved{}, fmt.Errorf("unknown social provider type %q", p.Type)
	}
	return r, nil
}

func defaultName(kind, id string) string {
	defer telemetry.Step("social.defaultName")()
	switch kind {
	case "google":
		return "Google"
	case "github":
		return "GitHub"
	case "facebook":
		return "Facebook"
	default:
		return id
	}
}

// AuthorizeURL builds the upstream redirect. challenge is empty when PKCE is off.
func AuthorizeURL(p Resolved, redirectURI, state, nonce, challenge string) (string, error) {
	defer telemetry.Step("social.AuthorizeURL")()
	if p.Authorization == "" {
		return "", fmt.Errorf("authorization endpoint is empty")
	}
	u, err := url.Parse(p.Authorization)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)
	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, p.ScopeSep))
	}
	if p.UsePKCE && challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	if p.UseIDToken && nonce != "" {
		q.Set("nonce", nonce)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
