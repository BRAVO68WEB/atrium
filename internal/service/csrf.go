package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

const CSRFCookie = "csrf_token"

// IssueCSRF returns the csrf_token cookie, creating it when it is missing.
// The cookie is HttpOnly and SameSite=Lax. Secure is set when the caller is on TLS.
func IssueCSRF(w http.ResponseWriter, r *http.Request, secure bool) string {
	defer telemetry.Step("service.IssueCSRF")()
	if r != nil {
		if c, err := r.Cookie(CSRFCookie); err == nil && c.Value != "" {
			return c.Value
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	token := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookie, Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure,
	})
	return token
}

// CSRFMatch compares the csrf_token form field with the cookie in constant time.
func CSRFMatch(r *http.Request) bool {
	defer telemetry.Step("service.CSRFMatch")()
	if r == nil {
		return false
	}
	c, err := r.Cookie(CSRFCookie)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.FormValue("csrf_token")
	if len(got) != len(c.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) == 1
}
