package mailer

import (
	"testing"

	"github.com/bravo68web/atrium/internal/config"
)

func TestSendRejectsHeaderInjection(t *testing.T) {
	m := &smtpMailer{cfg: config.SMTPConfig{Host: "127.0.0.1", Port: 1, From: "from@example.com"}}
	err := m.Send("ada@example.com\r\nBcc: eve@example.com", "Password reset", "hello")
	if err == nil {
		t.Fatal("expected a newline in the recipient to be rejected")
	}
}
