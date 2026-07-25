package service

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"text/template"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/gopkg/xlog"
)

// Mailer defines the interface for sending emails.
type Mailer interface {
	Send(to string, subject string, body string) error
}

// SMTPMailer implements the Mailer interface using SMTP.
type SMTPMailer struct {
	cfg config.SMTP
}

// NewSMTPMailer creates a new SMTPMailer.
func NewSMTPMailer(cfg config.SMTP) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

func (m *SMTPMailer) Send(to string, subject string, body string) error {
	// Defense in depth: to/subject ultimately land unescaped in the raw
	// SMTP command stream (Rcpt) and message headers below, so reject any
	// CR/LF that would let a malformed value inject extra SMTP commands or
	// mail headers, even if upstream validation is ever bypassed.
	if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		err := errors.New("email header injection attempt blocked")
		xlog.Error("refusing to send email with CR/LF in header value", "error", err)
		return err
	}

	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprintf("%d", m.cfg.Port))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		xlog.Error("failed to connect to SMTP server", "error", err)
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		xlog.Error("failed to create SMTP client", "error", err)
		return err
	}
	defer client.Close()

	tlsConfig := &tls.Config{ServerName: m.cfg.Host}
	if err := client.StartTLS(tlsConfig); err != nil {
		xlog.Error("SMTP server does not support TLS", "error", err)
		return err
	}

	if m.cfg.User != "" {
		auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			xlog.Error("failed to authenticate", "error", err)
			return err
		}
	}

	if err := client.Mail(m.cfg.From); err != nil {
		xlog.Error("failed to set mail sender", "error", err)
		return err
	}
	if err := client.Rcpt(to); err != nil {
		xlog.Error("failed to set mail recipient", "error", err)
		return err
	}

	w, err := client.Data()
	if err != nil {
		xlog.Error("failed to start mail data", "error", err)
		return err
	}
	msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", to, subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		xlog.Error("failed to write mail body", "error", err)
		return err
	}
	if err := w.Close(); err != nil {
		xlog.Error("failed to close mail data", "error", err)
		return err
	}

	return client.Quit()
}

// MockMailer implements the Mailer interface for testing purposes.
type MockMailer struct {
	SentEmails []map[string]string
}

// NewMockMailer creates a new MockMailer.
func NewMockMailer() *MockMailer {
	return &MockMailer{
		SentEmails: make([]map[string]string, 0),
	}
}

func (m *MockMailer) Send(to string, subject string, body string) error {
	m.SentEmails = append(m.SentEmails, map[string]string{
		"to":      to,
		"subject": subject,
		"body":    body,
	})
	xlog.Debug("mock email sent", "to", to, "subject", subject)
	return nil
}

// EmailTemplateData contains variables available in email templates.
type EmailTemplateData struct {
	Link  string // Full URL for the action (e.g., magic link URL)
	Token string // Raw token value
	Email string // User's email address
}

// RenderTemplate renders a template string with the given data.
// Returns the original template string if parsing or execution fails.
func RenderTemplate(tmpl string, data EmailTemplateData) string {
	t, err := template.New("email").Parse(tmpl)
	if err != nil {
		return tmpl
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return tmpl
	}

	return buf.String()
}
