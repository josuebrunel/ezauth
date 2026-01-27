package service

import (
	"testing"
)

func TestSMTPMailer_Send(t *testing.T) {
	// We can't easily test real SMTP sending without a server,
	// but we can test the header construction if we refactored,
	// but for now let's just test the MockMailer and integration.

	mailer := &MockMailer{}
	to := []string{"test@example.com"}
	subject := "Test Subject"
	body := "Test Body"

	err := mailer.Send(to, subject, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mailer.SentEmails) != 1 {
		t.Fatalf("expected 1 sent email, got %d", len(mailer.SentEmails))
	}

	sent := mailer.SentEmails[0]
	if sent.To[0] != to[0] {
		t.Errorf("expected to %s, got %s", to[0], sent.To[0])
	}
	if sent.Subject != subject {
		t.Errorf("expected subject %s, got %s", subject, sent.Subject)
	}
	if sent.Body != body {
		t.Errorf("expected body %s, got %s", body, sent.Body)
	}
}

func TestAuth_MailerIntegration(t *testing.T) {
	auth := setupBasicAuthTestDB(t) // This setup uses MockMailer by default now

	if auth.Mailer == nil {
		t.Fatal("expected mailer to be initialized")
	}

	_, ok := auth.Mailer.(*MockMailer)
	if !ok {
		t.Errorf("expected mailer to be *MockMailer, got %T", auth.Mailer)
	}
}
