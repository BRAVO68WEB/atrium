package mailer

import (
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
)

func TestMIMEMessageUsesHTMLWhenPresent(t *testing.T) {
	plain := mimeMessage("ada@example.com", "from@example.com", "Hi", "hello", "")
	if !strings.Contains(plain, "Content-Type: text/plain") || strings.Contains(plain, "multipart/alternative") {
		t.Fatalf("plain = %s", plain)
	}
	html := mimeMessage("ada@example.com", "from@example.com", "Hi", "hello", "<p>Hello</p>")
	if !strings.Contains(html, "multipart/alternative") || !strings.Contains(html, "Content-Type: text/html") || !strings.Contains(html, "<p>Hello</p>") {
		t.Fatalf("html = %s", html)
	}
}

func TestSendRejectsHeaderInjection(t *testing.T) {
	m := &smtpMailer{cfg: config.SMTPConfig{Host: "127.0.0.1", Port: 1, From: "from@example.com"}}
	err := m.Send("ada@example.com\r\nBcc: eve@example.com", "Password reset", "hello")
	if err == nil {
		t.Fatal("expected a newline in the recipient to be rejected")
	}
}
