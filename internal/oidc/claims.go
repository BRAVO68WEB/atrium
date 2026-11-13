package oidc

import (
	"strings"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func applyClaimMappings(mappings []config.ClaimMapping, subject string, user *models.User, scopes []string) map[string]any {
	defer telemetry.Step("oidc.applyClaimMappings")()
	if len(mappings) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, mapping := range mappings {
		if mapping.Claim == "" || reservedClaim(mapping.Claim) || !scopesCover(scopes, mapping.Scopes) {
			continue
		}
		value, ok := claimValue(mapping.Source, subject, user)
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

func claimValue(source, subject string, user *models.User) (any, bool) {
	defer telemetry.Step("oidc.claimValue")()
	if strings.HasPrefix(source, "const:") {
		return strings.TrimPrefix(source, "const:"), true
	}
	if source == "sub" {
		if subject != "" {
			return subject, true
		}
		if user != nil && user.ID != "" {
			return user.ID, true
		}
		return nil, false
	}
	if user == nil {
		return nil, false
	}
	switch source {
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
		return bagValue(user.Attributes, name)
	}
	if name, ok := strings.CutPrefix(source, "user."); ok && name != "" {
		return bagValue(user.UserMetadata, name)
	}
	return nil, false
}

func bagValue(bag map[string]string, name string) (any, bool) {
	defer telemetry.Step("oidc.bagValue")()
	if bag == nil {
		return nil, false
	}
	value, found := bag[name]
	return value, found
}
