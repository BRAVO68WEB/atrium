package service

import (
	"strings"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
	// ContentSecurityPolicy is the browser policy. Provider hosts are added only
	// while bot protection is configured. img-src allows https so an
	// organization logo_url can load.
)

func ContentSecurityPolicy(provider string) string {
	defer telemetry.Step("service.ContentSecurityPolicy")()
	script := []string{"'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"}
	connect := []string{"'self'", "https://cdn.jsdelivr.net"}
	var frame []string
	switch provider {
	case "recaptcha":
		script = append(script, "https://www.google.com", "https://www.gstatic.com")
		connect = append(connect, "https://www.google.com")
		frame = append(frame, "https://www.google.com", "https://www.gstatic.com")
	case "turnstile":
		script = append(script, "https://challenges.cloudflare.com")
		connect = append(connect, "https://challenges.cloudflare.com")
		frame = append(frame, "https://challenges.cloudflare.com")
	}
	policy := "default-src 'self'; script-src " + strings.Join(script, " ") +
		"; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https:; font-src 'self' https://cdn.jsdelivr.net; connect-src " +
		strings.Join(connect, " ")
	if len(frame) > 0 {
		policy += "; frame-src " + strings.Join(frame, " ")
	}
	return policy
}
