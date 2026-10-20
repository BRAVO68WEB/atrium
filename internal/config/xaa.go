package config

import (
	"fmt"
	"strings"
)

// Token type, grant, and profile URNs from
// draft-ietf-oauth-identity-assertion-authz-grant-04.
const (
	XAAIDJAGTokenType = "urn:ietf:params:oauth:token-type:id-jag"
	XAAJWTBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	XAAIDJAGProfile   = "urn:ietf:params:oauth:grant-profile:id-jag"
	XAAIDJAGTyp       = "oauth-id-jag+jwt"
)

// XAAConfig is Cross-App Access. Enabled stays false unless set, so a
// default server does not issue or accept an ID-JAG.
type XAAConfig struct {
	Enabled bool                  `yaml:"enabled"`
	Trusts  []XAATrust            `yaml:"trusts"`
	IDPs    []XAAIdentityProvider `yaml:"idps"`
}

// XAATrust is one app this IdP may send to a resource authorization server.
// ClientID is the app at this IdP. ResourceClientID is that app's client id
// at Audience.
type XAATrust struct {
	ClientID         string   `yaml:"client_id"`
	Audience         string   `yaml:"audience"`
	ResourceClientID string   `yaml:"resource_client_id"`
	Scopes           []string `yaml:"scopes"`
}

// XAAIdentityProvider is an issuer this server trusts when it is the
// resource authorization server.
type XAAIdentityProvider struct {
	Issuer  string   `yaml:"issuer"`
	JWKSURI string   `yaml:"jwks_uri"`
	Scopes  []string `yaml:"scopes"`
}

func (c *Config) normalizeXAA() {
	if c == nil {
		return
	}
	if c.XAA.Trusts == nil {
		c.XAA.Trusts = []XAATrust{}
	}
	if c.XAA.IDPs == nil {
		c.XAA.IDPs = []XAAIdentityProvider{}
	}
	for i := range c.XAA.Trusts {
		row := &c.XAA.Trusts[i]
		row.ClientID = strings.TrimSpace(row.ClientID)
		row.Audience = trimIssuer(row.Audience)
		row.ResourceClientID = strings.TrimSpace(row.ResourceClientID)
		row.Scopes = trimList(row.Scopes)
	}
	for i := range c.XAA.IDPs {
		row := &c.XAA.IDPs[i]
		row.Issuer = trimIssuer(row.Issuer)
		row.JWKSURI = strings.TrimSpace(row.JWKSURI)
		row.Scopes = trimList(row.Scopes)
	}
}

func trimIssuer(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

func trimList(values []string) []string {
	if values == nil {
		return []string{}
	}
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// ValidateXAA checks trust and identity-provider rows when the feature is
// on. A disabled block is left alone.
func ValidateXAA(c *Config) error {
	if c == nil || !c.XAA.Enabled {
		return nil
	}
	for i, row := range c.XAA.Trusts {
		if row.ClientID == "" || row.ResourceClientID == "" {
			return fmt.Errorf("xaa.trusts[%d] needs client_id and resource_client_id", i)
		}
		if !absoluteHTTP(row.Audience) {
			return fmt.Errorf("xaa.trusts[%d] audience is not an absolute url", i)
		}
		if len(row.Scopes) == 0 {
			return fmt.Errorf("xaa.trusts[%d] needs at least one scope", i)
		}
	}
	for i, row := range c.XAA.IDPs {
		if !absoluteHTTP(row.Issuer) {
			return fmt.Errorf("xaa.idps[%d] issuer is not an absolute url", i)
		}
		if !absoluteHTTP(row.JWKSURI) {
			return fmt.Errorf("xaa.idps[%d] jwks_uri is not an absolute url", i)
		}
		if len(row.Scopes) == 0 {
			return fmt.Errorf("xaa.idps[%d] needs at least one scope", i)
		}
	}
	return nil
}
