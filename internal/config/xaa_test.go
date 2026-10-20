package config

import "testing"

func TestXAADisabledSkipsBrokenRows(t *testing.T) {
	cfg := DefaultConfig()
	cfg.XAA.Trusts = []XAATrust{{Audience: "not a url"}}
	cfg.Normalize()
	if err := ValidateXAA(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestXAARejectsARelativeAudience(t *testing.T) {
	cfg := DefaultConfig()
	cfg.XAA.Enabled = true
	cfg.XAA.Trusts = []XAATrust{{
		ClientID:         "field-notes",
		Audience:         "notes.example",
		ResourceClientID: "notes-api",
		Scopes:           []string{"notes.read"},
	}}
	cfg.Normalize()
	if err := ValidateXAA(cfg); err == nil {
		t.Fatal("expected audience to fail")
	}
}

func TestXAATrimsTheAudienceSlash(t *testing.T) {
	cfg := DefaultConfig()
	cfg.XAA.Enabled = true
	cfg.XAA.Trusts = []XAATrust{{
		ClientID:         "field-notes",
		Audience:         "https://notes.example/",
		ResourceClientID: "notes-api",
		Scopes:           []string{" notes.read ", "notes.read"},
	}}
	cfg.XAA.IDPs = []XAAIdentityProvider{{
		Issuer:  "https://idp.example/",
		JWKSURI: "https://idp.example/oidc/jwks",
		Scopes:  []string{"notes.read"},
	}}
	cfg.Normalize()
	if err := ValidateXAA(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.XAA.Trusts[0].Audience != "https://notes.example" {
		t.Fatalf("audience %q", cfg.XAA.Trusts[0].Audience)
	}
	if len(cfg.XAA.Trusts[0].Scopes) != 1 || cfg.XAA.Trusts[0].Scopes[0] != "notes.read" {
		t.Fatalf("scopes %v", cfg.XAA.Trusts[0].Scopes)
	}
	if cfg.XAA.IDPs[0].Issuer != "https://idp.example" {
		t.Fatalf("issuer %q", cfg.XAA.IDPs[0].Issuer)
	}
}
