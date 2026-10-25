package service

import (
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

const ManagementScope = "management"

func StripManagement(scopes []string) []string {
	defer telemetry.Step("service.StripManagement")()
	if len(scopes) == 0 {
		return scopes
	}
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s != ManagementScope {
			out = append(out, s)
		}
	}
	return out
}

func HasScope(scopes []string, want string) bool {
	defer telemetry.Step("service.HasScope")()
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func HasGrant(grants []string, want string) bool {
	defer telemetry.Step("service.HasGrant")()
	for _, g := range grants {
		if g == want {
			return true
		}
	}
	return false
}

func AllowedScopes(requested string, clientScopes []string) ([]string, error) {
	defer telemetry.Step("service.AllowedScopes")()
	scopes := crypto.NormalizeScopes(requested)
	if len(scopes) == 0 {
		out := make([]string, len(clientScopes))
		copy(out, clientScopes)
		return out, nil
	}
	allowed := make(map[string]struct{}, len(clientScopes))
	for _, s := range clientScopes {
		allowed[s] = struct{}{}
	}
	for _, s := range scopes {
		if _, ok := allowed[s]; !ok {
			return nil, errInvalidScope(s)
		}
	}
	return scopes, nil
}

type scopeError string

func (e scopeError) Error() string { return string(e) }

func errInvalidScope(scope string) error {
	defer telemetry.Step("service.errInvalidScope")()
	return scopeError("scope " + scope + " is not allowed for this client")
}
