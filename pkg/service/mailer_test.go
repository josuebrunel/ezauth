package service

import (
	"strings"
	"sync"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
)

func TestMockMailer_ConcurrentSendIsRaceFree(t *testing.T) {
	m := NewMockMailer()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = m.Send("to@example.com", "subject", "body")
			_ = m.Emails() // concurrent read via the safe accessor
			_ = i
		}(i)
	}
	wg.Wait()

	if got := len(m.Emails()); got != 50 {
		t.Fatalf("expected 50 recorded emails, got %d", got)
	}
}

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
