package mailer

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/bravo68web/atrium/internal/telemetry"
)

// Data is the only value a mail template can read.
type Data struct {
	Issuer   string
	Username string
	Email    string
	Link     string
	Code     string
	TTL      string
	IP       string
	Time     string
	Agent    string
	Count    string
}

// Templates holds operator files. A nil set renders the built-in text.
// An optional name.html next to name.txt is the HTML part.
type Templates struct {
	parsed map[string]*template.Template
	html   map[string]*htmltemplate.Template
}

var builtinMail = map[string]string{
	"verify":           "Subject: Confirm your email\nConfirm your email:\n\n{{.Link}}\n",
	"reset":            "Subject: Password reset\nReset your password:\n\n{{.Link}}\n\nThis link expires in {{.TTL}}.\n",
	"password_changed": "Subject: Password changed\nThe password for {{.Username}} was changed.\n\nIf you did not do this, reset it from {{.Issuer}}/forgot\n",
	"new_sign_in":      "Subject: New sign-in\nNew sign-in for {{.Username}}\n\nTime: {{.Time}}\nIP: {{.IP}}\n",
	"login_failed":     "Subject: Failed sign-in attempts\n{{.Count}} failed sign-in attempts for {{.Username}} in the last 15 minutes.\n\nLatest IP: {{.IP}}\n",
	"migrate_otp":      "Subject: Your sign-in code\nYour sign-in code is {{.Code}}\n\nIt expires in {{.TTL}}. Enter it on the sign-in page, then choose a password.\n",
	"migrate_notice":   "Subject: Set a password to sign in\nSign in at {{.Issuer}}/login\n\nWe will email you a one-time code, then ask you to set a password.\n",
	"login_otp":        "Subject: Your sign-in code\nYour sign-in code is {{.Code}}\n\nIt expires in {{.TTL}}.\n",
	"login_link":       "Subject: Sign in\nOpen this link to sign in. It expires in {{.TTL}} and works once.\n\n{{.Link}}\n",
}

// Load reads templates_dir. An empty directory uses built-in text.
// A file that does not parse is an error. A missing file stays built-in.
func Load(dir string) (*Templates, error) {
	defer telemetry.Step("mailer.Load")()
	set := &Templates{
		parsed: map[string]*template.Template{},
		html:   map[string]*htmltemplate.Template{},
	}
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return set, nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("email.templates_dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("email.templates_dir must be a directory")
	}
	for name := range builtinMail {
		path := filepath.Join(dir, name+".txt")
		body, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("email template %s: %w", name, err)
		}
		if err == nil {
			parsed, err := parseMail(name, string(body))
			if err != nil {
				return nil, fmt.Errorf("email template %s: %w", name, err)
			}
			set.parsed[name] = parsed
		}
		htmlBody, err := os.ReadFile(filepath.Join(dir, name+".html"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("email template %s: %w", name, err)
		}
		htmlParsed, err := htmltemplate.New(name).Option("missingkey=error").Parse(string(htmlBody))
		if err != nil {
			return nil, fmt.Errorf("email template %s.html: %w", name, err)
		}
		set.html[name] = htmlParsed
	}
	return set, nil
}

// Render returns the subject and body for name.
func Render(set *Templates, name string, data Data) (string, string, error) {
	defer telemetry.Step("mailer.Render")()
	source := builtinMail[name]
	if source == "" {
		return "", "", fmt.Errorf("unknown email template %s", name)
	}
	var parsed *template.Template
	var err error
	if set != nil && set.parsed[name] != nil {
		parsed = set.parsed[name]
	} else {
		parsed, err = parseMail(name, source)
		if err != nil {
			return "", "", err
		}
	}
	var buf bytes.Buffer
	if err := parsed.Execute(&buf, data); err != nil {
		return "", "", err
	}
	text := buf.String()
	line, rest, ok := strings.Cut(text, "\n")
	if !ok || !strings.HasPrefix(line, "Subject: ") {
		return "", "", fmt.Errorf("email template %s is missing a subject", name)
	}
	return strings.TrimPrefix(line, "Subject: "), rest, nil
}

// RenderHTML returns the HTML part. An empty string means this message stays plain text.
func RenderHTML(set *Templates, name string, data Data) (string, error) {
	defer telemetry.Step("mailer.RenderHTML")()
	if set == nil || set.html[name] == nil {
		return "", nil
	}
	var buf bytes.Buffer
	if err := set.html[name].Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func parseMail(name, source string) (*template.Template, error) {
	defer telemetry.Step("mailer.parseMail")()
	line, _, ok := strings.Cut(source, "\n")
	if !ok || !strings.HasPrefix(line, "Subject: ") {
		return nil, fmt.Errorf("first line must start with Subject")
	}
	return template.New(name).Option("missingkey=error").Parse(source)
}
