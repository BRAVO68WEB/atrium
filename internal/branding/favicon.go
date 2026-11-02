package branding

import (
	_ "embed"
	"net/http"

	"github.com/bravo68web/atrium/internal/telemetry"
)

//go:embed mark.png
var defaultFavicon []byte

// ServeDefaultFavicon writes the built-in Atrium mark. Browsers request
// /favicon.ico even when a page names another icon.
func ServeDefaultFavicon(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("branding.ServeDefaultFavicon")()
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(defaultFavicon)
}
