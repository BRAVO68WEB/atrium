package oauth

import (
	"html"
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/branding"
	"github.com/bravo68web/oauth-impl/internal/oobcode"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// HandleOOBHelper serves the combined-code page from
// draft-richer-oauth-oob-authcode. It stays dark unless security.oob_helper
// is true. The authorization server still redirects here like any other
// registered redirect URI.
func (h *Handler) HandleOOBHelper(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleOOBHelper")()
	if h == nil || h.cfg == nil || !h.cfg.Security.OOBHelper {
		http.NotFound(w, r)
		return
	}
	query := r.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	if errCode := query.Get("error"); errCode != "" && code == "" {
		h.renderCombinedCode(w, "", state, errCode, query.Get("error_description"))
		return
	}
	if code == "" || state == "" {
		http.Error(w, "code and state are required", http.StatusBadRequest)
		return
	}
	combined, err := oobcode.Combine(code, state)
	if err != nil {
		http.Error(w, "code and state are required", http.StatusBadRequest)
		return
	}
	h.renderCombinedCode(w, combined, state, "", "")
}

func (h *Handler) renderCombinedCode(w http.ResponseWriter, combined, state, oauthError, description string) {
	defer telemetry.Step("oauth.Handler.renderCombinedCode")()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	data := map[string]any{
		"Combined":         combined,
		"State":            state,
		"Error":            oauthError,
		"ErrorDescription": description,
	}
	theme := branding.Theme{}
	if h != nil {
		theme = h.brandTheme
	}
	heading := "Paste this code"
	if oauthError != "" {
		heading = "Authorization stopped"
	}
	theme.Apply(data, "Authorization code", heading, "")
	if h != nil && h.pages != nil {
		if err := h.pages.ExecuteTemplate(w, "oob_helper.html", data); err == nil {
			return
		}
	}
	if oauthError != "" {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body><p>" + html.EscapeString(oauthError) + "</p></body></html>"))
		return
	}
	_, _ = w.Write([]byte("<!DOCTYPE html><html><body><input id=\"combined-code\" readonly value=\"" + html.EscapeString(combined) + "\"></body></html>"))
}
