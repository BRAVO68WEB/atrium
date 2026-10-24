package oauth

import (
	"html"
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/branding"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

const (
	outOfBandRedirect     = "urn:ietf:wg:oauth:2.0:oob"
	outOfBandRedirectAuto = "urn:ietf:wg:oauth:2.0:oob:auto"
)

// IsOutOfBandRedirect reports the two redirect URIs that show the
// authorization code on a page instead of sending the browser away.
func IsOutOfBandRedirect(uri string) bool {
	defer telemetry.Step("oauth.IsOutOfBandRedirect")()
	return uri == outOfBandRedirect || uri == outOfBandRedirectAuto
}

// RenderOutOfBand writes the paste-the-code page. An empty code with a
// non-empty oauthError is the failure page.
func (h *Handler) RenderOutOfBand(w http.ResponseWriter, clientID, code, state, oauthError, description string) {
	defer telemetry.Step("oauth.Handler.RenderOutOfBand")()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	data := map[string]any{
		"Code":             code,
		"State":            state,
		"Error":            oauthError,
		"ErrorDescription": description,
		"ClientID":         clientID,
	}
	theme := branding.Theme{}
	if h != nil {
		theme = h.brandTheme
	}
	heading := "Paste this code"
	if oauthError != "" {
		heading = "Authorization stopped"
	}
	clientName := ""
	if h != nil {
		clientName = h.ClientName(clientID)
	}
	theme.Apply(data, "Authorization code", heading, clientName)
	if h != nil && h.pages != nil {
		if err := h.pages.ExecuteTemplate(w, "oob.html", data); err == nil {
			return
		}
	}
	writeOutOfBandFallback(w, code, state, oauthError, description)
}

func writeOutOfBandFallback(w http.ResponseWriter, code, state, oauthError, description string) {
	defer telemetry.Step("oauth.writeOutOfBandFallback")()
	if oauthError != "" {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body><p>" + html.EscapeString(oauthError) + "</p><p>" + html.EscapeString(description) + "</p></body></html>"))
		return
	}
	_, _ = w.Write([]byte("<!DOCTYPE html><html><body><p>Paste this code into the application that asked you to sign in.</p><input id=\"authorization-code\" readonly value=\"" + html.EscapeString(code) + "\"><p>" + html.EscapeString(state) + "</p></body></html>"))
}
