package service

import (
	"strings"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
)

func TestSMTPMailer_RejectsHeaderInjection(t *testing.T) {
	// Host is deliberately unreachable/unset: these cases must be rejected
	// before any network dial is attempted, purely on CR/LF content.
	m := NewSMTPMailer(config.SMTP{Host: "", Port: 25, From: "noreply@example.com"})

	cases := []struct {
		name    string
		to      string
		subject string
	}{
		{"crlf in to", "victim@example.com\r\nBcc: attacker@evil.com", "hello"},
		{"lf in to", "victim@example.com\nBcc: attacker@evil.com", "hello"},
		{"crlf in subject", "victim@example.com", "hello\r\nBcc: attacker@evil.com"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := m.Send(c.to, c.subject, "body")
			if err == nil {
				t.Fatal("expected error for CR/LF in header value, got nil")
			}
			if !strings.Contains(err.Error(), "injection") {
				t.Errorf("expected injection-related error, got: %v", err)
			}
		})
	}
}
