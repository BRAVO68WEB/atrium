package mailer

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/config"
)

var ErrDisabled = fmt.Errorf("mailer disabled")

type Mailer interface {
	Enabled() bool
	Send(to, subject, text string) error
}

type Nop struct{}

func (Nop) Enabled() bool { return false }

func (Nop) Send(string, string, string) error { return ErrDisabled }

type smtpMailer struct {
	cfg config.SMTPConfig
}

func New(cfg config.SMTPConfig) (Mailer, error) {
	if !cfg.Enabled {
		return Nop{}, nil
	}
	if strings.TrimSpace(cfg.Host) == "" || strings.TrimSpace(cfg.From) == "" {
		return nil, fmt.Errorf("smtp.enabled requires smtp.host and smtp.from")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	return &smtpMailer{cfg: cfg}, nil
}

func (m *smtpMailer) Enabled() bool { return true }

func (m *smtpMailer) Send(to, subject, text string) error {
	toAddr, err := mailbox(to)
	if err != nil {
		return err
	}
	fromAddr, err := mailbox(m.cfg.From)
	if err != nil {
		return err
	}
	subject = oneLine(subject)
	if subject == "" {
		return fmt.Errorf("mail subject is empty")
	}
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	var conn net.Conn
	tlsConfig := &tls.Config{ServerName: m.cfg.Host}
	if m.cfg.ImplicitTLS {
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = client.Close() }()

	if !m.cfg.ImplicitTLS && m.cfg.StartTLS {
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if m.cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(fromAddr); err != nil {
		return err
	}
	if err := client.Rcpt(toAddr); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	safeText := sanitizeMailText(text)
	msg := fmt.Sprintf("To: %s\r\nFrom: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		toAddr, fromAddr, subject, safeText)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func sanitizeMailText(text string) string {
	// Normalize line endings to LF for predictable downstream handling.
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	// Remove control bytes that may be interpreted by downstream MTAs/parsers.
	// Keep LF and TAB to preserve plain-text formatting semantics.
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if (r >= 0x00 && r <= 0x1F) || r == 0x7F {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SanitizeText normalizes untrusted text before including it in email content.
func SanitizeText(text string) string {
	return sanitizeMailText(text)
}

// OneLine removes breaks and control characters from a single mail field.
func OneLine(text string) string {
	return oneLine(text)
}

func oneLine(text string) string {
	text = sanitizeMailText(text)
	text = strings.ReplaceAll(text, "\n", " ")
	return strings.Join(strings.Fields(text), " ")
}

// mailbox returns the addr-spec. A display name or an extra header is rejected.
func mailbox(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("invalid mail address")
	}
	addr, err := mail.ParseAddress(value)
	if err != nil {
		return "", fmt.Errorf("invalid mail address")
	}
	spec := strings.TrimSpace(addr.Address)
	if spec == "" || strings.ContainsAny(spec, "\r\n") || strings.ContainsAny(spec, " \t") {
		return "", fmt.Errorf("invalid mail address")
	}
	return spec, nil
}
