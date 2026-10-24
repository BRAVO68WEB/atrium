package oauth

import (
	"html"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"

	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleLogout")()
	if err := r.ParseForm(); err != nil && r.Method == http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost && !service.CSRFMatch(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "csrf_failed",
			"error_description": "CSRF token is missing or invalid",
		})
		return
	}
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		values = r.Form
	}
	idTokenHint := values.Get("id_token_hint")
	clientID := values.Get("client_id")
	redirectURI := values.Get("post_logout_redirect_uri")
	state := values.Get("state")
	confirmed := values.Get("confirm") == "yes"

	var hintSID, hintSub, hintAud string
	validHint := false
	if idTokenHint != "" && h.oidcHandler != nil {
		claims, err := h.oidcHandler.ParseSignedToken(idTokenHint)
		if err == nil {
			validHint = true
			hintSID, _ = claims["sid"].(string)
			hintSub, _ = claims["sub"].(string)
			hintAud = audienceOf(claims["aud"])
			if clientID != "" && hintAud != "" && hintAud != clientID {
				h.renderLogout(w, r, values, "id_token_hint audience does not match client_id")
				return
			}
		}
	}

	if !validHint && !confirmed {
		h.renderLogout(w, r, values, "")
		return
	}

	cookieSID := ""
	if cookie, err := r.Cookie("session_id"); err == nil {
		cookieSID = cookie.Value
	}
	endSession := func(sid string) {
		if sid == "" {
			return
		}
		if h.logout != nil {
			h.logout.End(sid)
		} else if h.sessions != nil {
			_ = h.sessions.Revoke(sid)
		}
	}
	if validHint && hintSID != "" {
		endSession(hintSID)
	}
	// A hint for another client names a different session. Leave this browser signed in.
	endCookie := !validHint && confirmed
	if validHint && hintSID != "" && cookieSID == hintSID {
		endCookie = true
	}
	if validHint && hintSID == "" && confirmed {
		endCookie = true
	}
	if endCookie && cookieSID != "" && cookieSID != hintSID {
		endSession(cookieSID)
	}
	if validHint && hintSID == "" && cookieSID == "" && hintSub != "" && h.sessions != nil {
		if ids, err := h.sessions.RevokeAllExcept(hintSub, ""); err == nil && h.logout != nil {
			for _, id := range ids {
				h.logout.Notify(id, hintSub)
			}
		}
	}
	if endCookie {
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   h.cfg.Server.TLS.Enabled,
			MaxAge:   -1,
		})
	}

	if !endCookie && hintSID == "" {
		h.renderLogout(w, r, values, "")
		return
	}

	if redirectURI != "" {
		if clientID == "" {
			h.renderLogout(w, r, values, "client_id is required with post_logout_redirect_uri")
			return
		}
		client, err := h.clientRepo.GetByID(clientID)
		if err != nil || client == nil || !isValidRedirectURI(redirectURI, client.PostLogoutRedirectURIs) || len(client.PostLogoutRedirectURIs) == 0 {
			h.renderLogout(w, r, values, "post_logout_redirect_uri is not registered")
			return
		}
		u, err := url.Parse(redirectURI)
		if err != nil || u.Scheme == "" || u.Host == "" {
			h.renderLogout(w, r, values, "post_logout_redirect_uri is not registered")
			return
		}
		if state != "" {
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
		}
		if isValidRedirectURI(redirectURI, client.PostLogoutRedirectURIs) {
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
		h.renderLogout(w, r, values, "post_logout_redirect_uri is not registered")
		return
	}

	h.renderLoggedOut(w)
}

func (h *Handler) renderLogout(w http.ResponseWriter, r *http.Request, values url.Values, errMsg string) {
	defer telemetry.Step("oauth.Handler.renderLogout")()
	data := map[string]any{
		"Error":                 errMsg,
		"IDTokenHint":           values.Get("id_token_hint"),
		"ClientID":              values.Get("client_id"),
		"PostLogoutRedirectURI": values.Get("post_logout_redirect_uri"),
		"State":                 values.Get("state"),
		"Done":                  false,
		"CSRFToken":             service.IssueCSRF(w, r, h.cfg != nil && h.cfg.Server.TLS.Enabled),
	}
	h.brandTheme.Apply(data, "Sign Out", "Sign out", "")
	if h.pages != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.pages.ExecuteTemplate(w, "logout.html", data); err == nil {
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>Sign out</h1><p>` + html.EscapeString(errMsg) + `</p>
<form method="POST" action="/oauth/logout">
<input type="hidden" name="csrf_token" value="` + html.EscapeString(data["CSRFToken"].(string)) + `">
<input type="hidden" name="confirm" value="yes">
<input type="hidden" name="id_token_hint" value="` + html.EscapeString(values.Get("id_token_hint")) + `">
<input type="hidden" name="client_id" value="` + html.EscapeString(values.Get("client_id")) + `">
<input type="hidden" name="post_logout_redirect_uri" value="` + html.EscapeString(values.Get("post_logout_redirect_uri")) + `">
<input type="hidden" name="state" value="` + html.EscapeString(values.Get("state")) + `">
<button type="submit">Sign out</button>
</form></body></html>`))
}

func (h *Handler) renderLoggedOut(w http.ResponseWriter) {
	defer telemetry.Step("oauth.Handler.renderLoggedOut")()
	data := map[string]any{"Error": "", "Done": true}
	h.brandTheme.Apply(data, "Sign Out", "Signed out", "")
	if h.pages != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.pages.ExecuteTemplate(w, "logout.html", data); err == nil {
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><h1>Signed out</h1></body></html>`))
}

func audienceOf(raw any) string {
	defer telemetry.Step("oauth.audienceOf")()
	switch v := raw.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			s, _ := v[0].(string)
			return s
		}
	case jwt.ClaimStrings:
		if len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func containsString(list []string, want string) bool {
	defer telemetry.Step("oauth.containsString")()
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
