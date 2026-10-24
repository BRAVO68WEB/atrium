package controller

import (
	"encoding/base64"
	"html"
	"net/http"
	"sort"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/go-chi/chi/v5"
	qrcode "github.com/skip2/go-qrcode"
)

type previewPage struct {
	Name     string
	Label    string
	Variants []string
	render   func(variant string) previewView
}

type previewView struct {
	Page       string
	Title      string
	Heading    string
	ClientName string
	Params     map[string]string
	Extra      map[string]any
}

func previewCatalog() []previewPage {
	defer telemetry.Step("controller.previewCatalog")()
	sample := map[string]string{
		"client_id":     "preview-app",
		"redirect_uri":  "https://app.example/cb",
		"response_type": "code",
		"scope":         "openid profile email",
		"state":         "preview-state",
	}
	orgs := []*models.Organization{
		{Name: "Field Notes", Slug: "field-notes"},
		{Name: "Archive", Slug: "archive"},
	}
	return []previewPage{
		{Name: "login", Label: "Login", Variants: []string{"", "client", "error", "social"}, render: func(variant string) previewView {
			extra := map[string]any{}
			client := ""
			switch variant {
			case "client", "social":
				client = "Field Notes"
			case "error":
				client = "Field Notes"
				extra["Error"] = "Invalid credentials"
			}
			if variant == "social" {
				extra["Providers"] = []service.SocialButton{{ID: "google", Name: "Google"}, {ID: "github", Name: "GitHub"}}
			}
			return previewView{Page: "login.html", Title: "Login", Heading: "Sign In", ClientName: client, Params: sample, Extra: extra}
		}},
		{Name: "register", Label: "Register", Variants: []string{"", "error"}, render: func(variant string) previewView {
			extra := map[string]any{}
			if variant == "error" {
				extra["Error"] = "That username is already taken"
			}
			return previewView{Page: "register.html", Title: "Register", Heading: "Create Account", ClientName: "Field Notes", Params: sample, Extra: extra}
		}},
		{Name: "consent", Label: "Consent", Variants: []string{"", "actor"}, render: func(variant string) previewView {
			extra := map[string]any{
				"Username": "ada",
				"Scopes":   []string{"openid", "profile", "email", "notes.read"},
			}
			if variant == "actor" {
				extra["ActorName"] = "Finance Agent"
			}
			return previewView{Page: "consent.html", Title: "Authorize", Heading: "Authorize Access", ClientName: "Field Notes", Params: sample, Extra: extra}
		}},
		{Name: "mfa", Label: "MFA code", Variants: []string{"", "error"}, render: func(variant string) previewView {
			extra := map[string]any{}
			if variant == "error" {
				extra["Error"] = "That code is not valid"
			}
			return previewView{Page: "mfa.html", Title: "Two-factor", Heading: "Enter the code", ClientName: "Field Notes", Params: sample, Extra: extra}
		}},
		{Name: "mfa-enroll", Label: "MFA enrollment", Variants: []string{""}, render: func(string) previewView {
			return previewView{Page: "mfa_enroll.html", Title: "Set up authenticator", Heading: "Set up an authenticator", ClientName: "Field Notes", Params: sample, Extra: map[string]any{
				"QRCodeBase64": previewQR("otpauth://totp/Northwind:ada?secret=JBSWY3DPEHPK3PXP"),
				"Secret":       "JBSWY3DPEHPK3PXP",
				"Issuer":       "Northwind",
				"Username":     "ada",
			}}
		}},
		{Name: "profile", Label: "Profile", Variants: []string{"", "empty", "unverified", "mfa"}, render: func(variant string) previewView {
			extra := map[string]any{
				"Username": "ada", "Email": "ada@fieldnotes.example", "EmailVerified": true,
				"MFAEnabled": false, "Removed": false,
				"Sessions": []profileSession{{ID: "current", Detail: "127.0.0.1 · 12 Oct 2026 09:00", Current: true}},
			}
			switch variant {
			case "empty":
				extra["Sessions"] = []profileSession{}
			case "unverified":
				extra["EmailVerified"] = false
			case "mfa":
				extra["MFAEnabled"] = true
			default:
				extra["Grants"] = []profileGrant{{
					ClientID: "field-notes",
					Name:     "Field Notes",
					Initial:  "F",
					Detail:   "openid profile email · 12 Oct 2026",
					Color:    "#1d4ed8",
				}}
				extra["Sessions"] = []profileSession{
					{ID: "current", Detail: "127.0.0.1 · 12 Oct 2026 09:00", Current: true},
					{ID: "other", Detail: "203.0.113.10 · Firefox · 11 Oct 2026 18:12", Current: false},
				}
			}
			return previewView{Page: "profile.html", Title: "Account", Heading: "Your account", ClientName: "Field Notes", Params: sample, Extra: extra}
		}},
		{Name: "organization", Label: "Organization", Variants: []string{""}, render: func(string) previewView {
			return previewView{Page: "organization.html", Title: "Organization", Heading: "Choose an organization", ClientName: "Field Notes", Params: sample, Extra: map[string]any{
				"Username": "ada",
				"Orgs":     orgs,
			}}
		}},
		{Name: "device", Label: "Device approval", Variants: []string{"", "confirm", "approved", "denied"}, render: func(variant string) previewView {
			extra := map[string]any{"UserCode": "ABCD-EFGH", "Done": false, "Approved": false, "Confirm": false}
			switch variant {
			case "confirm":
				extra["Confirm"] = true
				extra["ClientName"] = "Field Notes"
				extra["Scopes"] = []string{"openid", "profile"}
			case "approved":
				extra["Done"] = true
				extra["Approved"] = true
			case "denied":
				extra["Done"] = true
			}
			return previewView{Page: "device.html", Title: "Device", Heading: "Approve a device", ClientName: "Field Notes", Params: sample, Extra: extra}
		}},
		{Name: "oob", Label: "Out-of-band code", Variants: []string{"", "error"}, render: func(variant string) previewView {
			extra := map[string]any{"Code": "a1b2c3d4e5f6", "State": "preview-state"}
			if variant == "error" {
				extra = map[string]any{"Error": "access_denied", "ErrorDescription": "The request was denied."}
			}
			return previewView{Page: "oob.html", Title: "Code", Heading: "Copy this code", Extra: extra}
		}},
		{Name: "oob-helper", Label: "Combined code", Variants: []string{"", "error"}, render: func(variant string) previewView {
			extra := map[string]any{"Combined": "NJcnjhk1_VVaQXYs6yQ"}
			if variant == "error" {
				extra = map[string]any{"Error": "access_denied", "ErrorDescription": "The request was denied."}
			}
			return previewView{Page: "oob_helper.html", Title: "Code", Heading: "Copy this code", Extra: extra}
		}},
		{Name: "push-enroll", Label: "Push enrollment", Variants: []string{""}, render: func(string) previewView {
			raw := "https://issuer.example/push/enroll#eyJhbGciOiJSUzI1NiJ9.preview.signature"
			return previewView{Page: "push_enroll.html", Title: "Add an authenticator", Heading: "Add an authenticator", Extra: map[string]any{
				"QRCodeBase64":      previewQR(raw),
				"EnrollURL":         raw,
				"RegistrationToken": "eyJhbGciOiJSUzI1NiJ9.preview.signature",
			}}
		}},
		{Name: "push-approve", Label: "Push approval", Variants: []string{"", "approved", "empty"}, render: func(variant string) previewView {
			extra := map[string]any{"Pending": true, "AuthReqID": "preview-auth", "BindingMessage": "42"}
			switch variant {
			case "approved":
				extra = map[string]any{"Approved": true, "Pending": false}
			case "empty":
				extra = map[string]any{"Pending": false}
			}
			return previewView{Page: "push_approve.html", Title: "Sign-in", Heading: "Approve this sign-in", Extra: extra}
		}},
		{Name: "forgot", Label: "Forgot password", Variants: []string{"", "sent"}, render: func(variant string) previewView {
			extra := map[string]any{}
			if variant == "sent" {
				extra["Status"] = "If that account exists, a reset link is on its way."
			}
			return previewView{Page: "forgot.html", Title: "Forgot password", Heading: "Reset your password", Extra: extra}
		}},
		{Name: "reset", Label: "Reset password", Variants: []string{"", "done"}, render: func(variant string) previewView {
			extra := map[string]any{"Token": "preview-reset-token"}
			if variant == "done" {
				extra["Done"] = true
			}
			return previewView{Page: "reset.html", Title: "New password", Heading: "Choose a new password", Extra: extra}
		}},
		{Name: "verify-email", Label: "Email verification", Variants: []string{""}, render: func(string) previewView {
			return previewView{Page: "verify_email.html", Title: "Email", Heading: "Email verified", Extra: map[string]any{
				"Message": "Your email address is verified.",
			}}
		}},
		{Name: "logout", Label: "Sign out", Variants: []string{"", "done"}, render: func(variant string) previewView {
			extra := map[string]any{"ClientID": "preview-app", "State": "preview-state"}
			if variant == "done" {
				extra["Done"] = true
			}
			return previewView{Page: "logout.html", Title: "Sign out", Heading: "Sign out", Extra: extra}
		}},
	}
}

// PreviewEnabled reports whether /preview is mounted.
func (c *WebController) PreviewEnabled() bool {
	defer telemetry.Step("controller.WebController.PreviewEnabled")(

	// HandlePreview renders one auth page with sample data, or the catalog.
	)
	return c != nil && c.cfg != nil && c.cfg.Debug.UI
}

func (c *WebController) HandlePreview(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.WebController.HandlePreview")()
	if !c.PreviewEnabled() {
		http.NotFound(w, r)
		return
	}
	name := chi.URLParam(r, "page")
	if name == "" {
		c.writePreviewIndex(w)
		return
	}
	var spec previewPage
	found := false
	for _, item := range previewCatalog() {
		if item.Name == name {
			spec = item
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	view := spec.render(r.URL.Query().Get("variant"))
	if view.Params == nil {
		view.Params = map[string]string{}
	}
	c.renderPreview(w, r, view)
}

func (c *WebController) renderPreview(w http.ResponseWriter, r *http.Request, view previewView) {
	defer telemetry.Step("controller.WebController.renderPreview")()
	if view.Extra == nil {
		view.Extra = map[string]any{}
	}
	secure := c != nil && c.cfg != nil && c.cfg.Server.TLS.Enabled
	view.Extra["CSRFToken"] = issueCSRF(w, r, secure)
	if c != nil && c.cfg != nil {
		view.Extra["BotProvider"] = c.cfg.Security.BotProtection.Provider
		view.Extra["BotSiteKey"] = c.cfg.Security.BotProtection.SiteKey
	}
	data := oauthTemplateData(view.Params, view.Extra)
	c.theme.Apply(data, view.Title, view.Heading, view.ClientName)
	if _, ok := view.Extra["Providers"]; !ok && c.social != nil && view.Page == "login.html" {
		data["Providers"] = c.social.Buttons()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := c.templates.ExecuteTemplate(w, view.Page, data); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}

func (c *WebController) writePreviewIndex(w http.ResponseWriter) {
	defer telemetry.Step("controller.WebController.writePreviewIndex")()
	pages := previewCatalog()
	sort.Slice(pages, func(i, j int) bool { return pages[i].Label < pages[j].Label })
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>UI preview</title>
<style>
body{margin:0;background:#f4f5f7;color:#18181b;font:16px/1.5 "Segoe UI","Helvetica Neue",sans-serif}
main{max-width:640px;margin:48px auto;padding:0 20px}
h1{font-weight:600;font-size:1.5rem;letter-spacing:-0.02em;margin:0 0 8px}
p{color:#3f3f46;margin:0 0 24px}
ul{list-style:none;padding:0;margin:0}
li{padding:14px 0;border-top:1px solid #e4e4e7}
a{color:#0066ff;font-weight:600;text-decoration:none;margin-right:12px}
a:hover{text-decoration:underline;text-underline-offset:3px}
</style></head><body><main><h1>UI preview</h1><p>Sample auth screens. Submitting a form uses the real endpoint.</p><ul>`))
	for _, page := range pages {
		_, _ = w.Write([]byte("<li><a href=\"/preview/" + html.EscapeString(page.Name) + "\">" + html.EscapeString(page.Label) + "</a>"))
		for _, variant := range page.Variants {
			if variant == "" {
				continue
			}
			_, _ = w.Write([]byte("<a href=\"/preview/" + html.EscapeString(page.Name) + "?variant=" + html.EscapeString(variant) + "\">" + html.EscapeString(variant) + "</a>"))
		}
		_, _ = w.Write([]byte("</li>"))
	}
	_, _ = w.Write([]byte("</ul></main></body></html>"))
}

func previewQR(text string) string {
	defer telemetry.Step("controller.previewQR")()
	png, err := qrcode.Encode(text, qrcode.Medium, 256)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(png)
}
