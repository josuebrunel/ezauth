package service

import (
	"fmt"
	"net/smtp"

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
	auth := smtp.PlainAuth("", m.cfg.User, m.cfg.Password, m.cfg.Host)
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", to, subject, body))
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)

	if err := smtp.SendMail(addr, auth, m.cfg.From, []string{to}, msg); err != nil {
		xlog.Error("failed to send email", "error", err, "to", to)
		return err
	}
	return nil
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
