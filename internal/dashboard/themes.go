package dashboard

import (
	"html"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/controller"
	"github.com/bravo68web/atrium/internal/mailer"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// Pages renders the auth screens with sample data.
type Pages interface {
	PreviewPages() []controller.PreviewPage
	ServePagePreview(http.ResponseWriter, *http.Request, string, string)
}

var mailLabels = map[string]string{
	"verify":           "Confirm email",
	"reset":            "Password reset",
	"password_changed": "Password changed",
	"new_sign_in":      "New sign-in",
	"login_failed":     "Failed sign-in",
	"migrate_otp":      "Migration code",
	"migrate_notice":   "Set a password",
	"login_otp":        "Sign-in code",
	"login_link":       "Sign-in link",
}

func (h *Handler) themePages(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.themePages")()
	pages := []controller.PreviewPage{}
	if h.pages != nil {
		pages = h.pages.PreviewPages()
	}
	writeJSON(w, http.StatusOK, map[string]any{"pages": pages})
}

func (h *Handler) themeEmail(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.themeEmail")()
	set, err := h.mailTemplates()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	data := mailer.SampleData(h.issuer())
	out := make([]map[string]any, 0, len(mailer.TemplateNames()))
	for _, name := range mailer.TemplateNames() {
		subject, text, err := mailer.Render(set, name, data)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		source := "builtin"
		if set.UsesFile(name) {
			source = "file"
		}
		out = append(out, map[string]any{
			"name":    name,
			"label":   mailLabels[name],
			"subject": subject,
			"text":    text,
			"html":    set.HasHTML(name),
			"source":  source,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"emails": out})
}

func (h *Handler) previewPage(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.previewPage")()
	if h.pages == nil {
		http.NotFound(w, r)
		return
	}
	h.pages.ServePagePreview(w, r, chi.URLParam(r, "name"), r.URL.Query().Get("variant"))
}

func (h *Handler) previewEmail(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.previewEmail")()
	name := chi.URLParam(r, "name")
	set, err := h.mailTemplates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data := mailer.SampleData(h.issuer())
	subject, text, err := mailer.Render(set, name, data)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	part, err := mailer.RenderHTML(set, name, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'")
	_, _ = w.Write([]byte(emailDocument(subject, text, part)))
}

func (h *Handler) mailTemplates() (*mailer.Templates, error) {
	dir := ""
	if h.cfg != nil {
		dir = h.cfg.Email.TemplatesDir
	}
	return mailer.Load(dir)
}

func (h *Handler) issuer() string {
	if h.cfg == nil {
		return ""
	}
	issuer := strings.TrimRight(h.cfg.OIDC.Issuer, "/")
	if issuer == "" {
		issuer = strings.TrimRight(h.cfg.Security.Issuer, "/")
	}
	return issuer
}

func emailDocument(subject, text, part string) string {
	if strings.Contains(strings.ToLower(part), "<html") {
		return part
	}
	body := "<pre style=\"white-space:pre-wrap;font:15px/1.5 ui-monospace,monospace;margin:24px;color:#18181b\">" + html.EscapeString(text) + "</pre>"
	if part != "" {
		body = part
	}
	return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>" + html.EscapeString(subject) + "</title></head><body style=\"margin:0;background:#f4f4f5\">" + body + "</body></html>"
}
