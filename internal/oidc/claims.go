package oidc

import (
	"strings"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func applyClaimMappings(mappings []config.ClaimMapping, user *models.User, scopes []string) map[string]any {
	defer telemetry.Step("oidc.applyClaimMappings")()
	if len(mappings) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, mapping := range mappings {
		if mapping.Claim == "" || reservedClaim(mapping.Claim) || !scopesCover(scopes, mapping.Scopes) {
			continue
		}
		value, ok := claimValue(mapping.Source, user)
		if !ok {
			continue
		}
		out[mapping.Claim] = value
	}
	return out
}

func reservedClaim(claim string) bool {
	defer telemetry.Step("oidc.reservedClaim")()
	switch claim {
	case "iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "sid", "auth_time", "org_id", "org_slug", "org_role":
		return true
	default:
		return false
	}
}

func scopesCover(have, need []string) bool {
	defer telemetry.Step("oidc.scopesCover")()
	if len(need) == 0 {
		return true
	}
	set := map[string]bool{}
	for _, scope := range have {
		set[scope] = true
	}
	for _, scope := range need {
		if !set[scope] {
			return false
		}
	}
	return true
}

func claimValue(source string, user *models.User) (any, bool) {
	defer telemetry.Step("oidc.claimValue")()
	if strings.HasPrefix(source, "const:") {
		return strings.TrimPrefix(source, "const:"), true
	}
	if user == nil {
		return nil, false
	}
	switch source {
	case "sub":
		return user.ID, user.ID != ""
	case "username":
		return user.Username, true
	case "email":
		return user.Email, true
	case "email_verified":
		return user.EmailVerified, true
	case "phone":
		return user.PhoneNumber, true
	case "given_name":
		return user.GivenName, true
	case "family_name":
		return user.FamilyName, true
	}
	if name, ok := strings.CutPrefix(source, "attr."); ok && name != "" {
		if user.Attributes == nil {
			return nil, false
		}
		value, found := user.Attributes[name]
		return value, found
	}
	return nil, false
}
