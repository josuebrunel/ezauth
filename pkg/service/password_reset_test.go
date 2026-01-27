package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

func TestPasswordReset(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	// 1. Create a user
	email := "reset@example.com"
	password := "old-password"
	user := &models.User{
		Email:    email,
		Provider: "local",
	}
	user.PasswordHash, _ = auth.UserHashPassword(password)
	createdUser, err := auth.Repo.UserCreate(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// 2. Request password reset
	err = auth.PasswordResetRequest(ctx, RequestPasswordReset{Email: email})
	if err != nil {
		t.Fatalf("PasswordResetRequest() failed: %v", err)
	}

	// Get token from mock mailer (Wait, I need to cast it)
	mockMailer := auth.Mailer.(*MockMailer)
	if len(mockMailer.SentEmails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mockMailer.SentEmails))
	}

	// Extract token from body - "You requested a password reset. Please use the following token: <token>"
	sentBody := mockMailer.SentEmails[0]["body"]
	tokenValue := sentBody[len(sentBody)-64:] // It's a 32-byte hex string = 64 chars

	// 3. Confirm password reset
	newPassword := "new-password"
	err = auth.PasswordResetConfirm(ctx, RequestPasswordResetConfirm{
		Token:    tokenValue,
		Password: newPassword,
	})
	if err != nil {
		t.Fatalf("PasswordResetConfirm() failed: %v", err)
	}

	// 4. Verify new password works
	authenticatedUser, err := auth.UserAuthenticate(ctx, RequestBasicAuth{
		Email:    email,
		Password: newPassword,
	})
	if err != nil {
		t.Fatalf("UserAuthenticate() failed after reset: %v", err)
	}
	if authenticatedUser.ID != createdUser.ID {
		t.Errorf("expected user id %s, got %s", createdUser.ID, authenticatedUser.ID)
	}

	// 5. Verify token is revoked
	storedToken, _ := auth.Repo.TokenGetByToken(ctx, tokenValue)
	if !storedToken.Revoked {
		t.Error("expected token to be revoked after use")
	}

	// 6. Try to use the same token again
	err = auth.PasswordResetConfirm(ctx, RequestPasswordResetConfirm{
		Token:    tokenValue,
		Password: "another-password",
	})
	if err == nil {
		t.Error("expected error when using revoked token, got nil")
	}
}
