package service

import (
	"context"
	"testing"
)

func TestPasswordless(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	email := "magic@example.com"

	// 1. Request magic link
	err := auth.PasswordlessRequest(ctx, RequestPasswordless{Email: email})
	if err != nil {
		t.Fatalf("PasswordlessRequest() failed: %v", err)
	}

	mockMailer := auth.Mailer.(*MockMailer)
	if len(mockMailer.SentEmails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mockMailer.SentEmails))
	}

	sentBody := mockMailer.SentEmails[0]["body"]
	// body := fmt.Sprintf("Click the following link to login: http://%s/auth/passwordless/login?token=%s", a.Cfg.Addr, tokenValue)
	tokenValue := sentBody[len(sentBody)-64:]

	// 2. Login with magic link
	resp, err := auth.PasswordlessLogin(ctx, tokenValue)
	if err != nil {
		t.Fatalf("PasswordlessLogin() failed: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected access token")
	}

	// 3. Verify user was created
	user, err := auth.Repo.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if user.Email != email {
		t.Errorf("expected email %s, got %s", email, user.Email)
	}
	if !user.EmailVerified {
		t.Error("expected email to be verified")
	}

	// 4. Verify token was deleted
	_, err = auth.Repo.PasswordlessTokenGetByToken(ctx, tokenValue)
	if err == nil {
		t.Error("expected token to be deleted after use, but it still exists")
	}
}
