package config

import "testing"

func TestOrgFlagsDefaultOff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Org.Enabled || cfg.Org.EnabledDomainBasedAutolookup {
		t.Fatalf("org flags = %+v", cfg.Org)
	}
}

func TestLoginIdentifier(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Normalize()
	if cfg.Security.LoginIdentifier != "username" {
		t.Fatalf("identifier = %q", cfg.Security.LoginIdentifier)
	}
	cfg.Security.LoginIdentifier = "EMAIL"
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err != nil || cfg.Security.LoginIdentifier != "email" {
		t.Fatalf("identifier = %q err %v", cfg.Security.LoginIdentifier, err)
	}
	cfg.Security.LoginIdentifier = "phone"
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestPasswordlessMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.DisablePasswords = true
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err != nil || cfg.Security.PasswordlessMode != "otp" {
		t.Fatalf("mode = %q err %v", cfg.Security.PasswordlessMode, err)
	}
	cfg.Security.PasswordlessMode = "LINK"
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err != nil || cfg.Security.PasswordlessMode != "link" {
		t.Fatalf("mode = %q err %v", cfg.Security.PasswordlessMode, err)
	}
	cfg.Security.PasswordlessMode = "sms"
	cfg.Normalize()
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDomainAutolookupRequiresOrgs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Org.EnabledDomainBasedAutolookup = true
	if err := ValidatePlatform(cfg); err == nil {
		t.Fatal("expected validation error")
	}
	cfg.Org.Enabled = true
	if err := ValidatePlatform(cfg); err != nil {
		t.Fatal(err)
	}
}
