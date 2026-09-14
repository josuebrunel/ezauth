package service

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestSMTPMailer_DoesNotHangOnAStalledServer proves Send returns (with an
// error) instead of blocking forever against a server that accepts the TCP
// connection but never sends its greeting banner -- net.Dial (no timeout)
// plus no conn.SetDeadline previously meant this would hang indefinitely.
func TestSMTPMailer_DoesNotHangOnAStalledServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept the connection and then do nothing -- simulates a stalled
		// server that never sends the SMTP greeting banner smtp.NewClient
		// waits to read.
		time.Sleep(5 * time.Second)
	}()

	oldTimeout := smtpTimeout
	smtpTimeout = 200 * time.Millisecond
	defer func() { smtpTimeout = oldTimeout }()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse listener address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse listener port: %v", err)
	}

	m := NewSMTPMailer(config.SMTP{Host: host, Port: port, From: "noreply@example.com"})

	done := make(chan error, 1)
	go func() { done <- m.Send("to@example.com", "subject", "body") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from a stalled SMTP server, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not return within 2s of a 200ms deadline -- it's hanging on the stalled connection")
	}
}
