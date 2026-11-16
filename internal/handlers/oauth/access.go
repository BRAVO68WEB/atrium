package oauth

import (
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func (h *Handler) SetAccess(access *service.AccessService) {
	defer telemetry.Step("oauth.Handler.SetAccess")()
	if h != nil {
		h.access = access
	}
}

func (h *Handler) narrowScopes(userID, orgID string, scopes []string) ([]string, error) {
	defer telemetry.Step("oauth.Handler.narrowScopes")()
	if h == nil || h.access == nil || userID == "" {
		return scopes, nil
	}
	return h.access.Narrow(userID, orgID, scopes)
}
