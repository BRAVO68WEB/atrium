package dashboard

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

const dashboardCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", dashboardCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	name := strings.TrimPrefix(r.URL.Path, "/dashboard")
	name = strings.TrimPrefix(name, "/")
	assets := assetFS()
	if name == "" || !isFile(assets, name) {
		name = "index.html"
	}
	body, err := fs.ReadFile(assets, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		if ctype := mime.TypeByExtension(path.Ext(name)); ctype != "" {
			w.Header().Set("Content-Type", ctype)
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func isFile(assets fs.FS, name string) bool {
	info, err := fs.Stat(assets, name)
	return err == nil && !info.IsDir()
}
