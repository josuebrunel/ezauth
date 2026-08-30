package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func setupEmailChangeTestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("email_change_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		EmailTemplates: config.EmailTemplates{
			EmailChangeSubject:       "Confirm your new email address",
			EmailChangeBody:          "Click the following link to confirm your new email address: {{.Link}}",
			EmailChangeNotifySubject: "Your email address is being changed",
			EmailChangeNotifyBody:    "A request was made to change the email on your account to {{.NewEmail}}.",
		},
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := migrations.MigrateUpWithDBConn(auth.Repo.DB(), dialect); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func TestEmailChangeFlow(t *testing.T) {
	auth := setupEmailChangeTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("emailchange")
	password := "securepass123"
	user, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password})
	if err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	newEmail := util.UniqueEmail("emailchangenew")

	t.Run("request rejects wrong current password", func(t *testing.T) {
		if err := auth.EmailChangeRequest(ctx, user, RequestEmailChange{CurrentPassword: "wrong", NewEmail: newEmail}); err != ErrIncorrectPassword {
			t.Fatalf("expected ErrIncorrectPassword, got %v", err)
		}
	})

	t.Run("request rejects an already-registered new email", func(t *testing.T) {
		other, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: util.UniqueEmail("other"), Password: password})
		if err != nil {
			t.Fatalf("UserCreate failed: %v", err)
		}
		if err := auth.EmailChangeRequest(ctx, user, RequestEmailChange{CurrentPassword: password, NewEmail: other.Email}); err != ErrEmailAlreadyRegistered {
			t.Fatalf("expected ErrEmailAlreadyRegistered, got %v", err)
		}
	})

	t.Run("request sends a verification email to the new address and a notice to the old one", func(t *testing.T) {
		if err := auth.EmailChangeRequest(ctx, user, RequestEmailChange{CurrentPassword: password, NewEmail: newEmail}); err != nil {
			t.Fatalf("EmailChangeRequest failed: %v", err)
		}

		mockMailer := auth.Mailer.(*MockMailer)
		if len(mockMailer.SentEmails) != 2 {
			t.Fatalf("expected 2 emails sent, got %d", len(mockMailer.SentEmails))
		}
		if mockMailer.SentEmails[0]["to"] != newEmail {
			t.Fatalf("expected first email to go to the new address, got %q", mockMailer.SentEmails[0]["to"])
		}
		if mockMailer.SentEmails[1]["to"] != email {
			t.Fatalf("expected second email (notice) to go to the old address, got %q", mockMailer.SentEmails[1]["to"])
		}

		// The account's email must not change until confirmation.
		unchanged, err := auth.Repo.UserGetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if unchanged.Email != email {
			t.Fatalf("expected email to remain %q until confirmed, got %q", email, unchanged.Email)
		}
	})

	mockMailer := auth.Mailer.(*MockMailer)
	verificationBody := mockMailer.SentEmails[len(mockMailer.SentEmails)-2]["body"]
	tokenValue := verificationBody[len(verificationBody)-64:]

	var refreshToken string
	t.Run("session exists before confirm", func(t *testing.T) {
		resp, err := auth.TokenCreate(ctx, user)
		if err != nil {
			t.Fatalf("TokenCreate failed: %v", err)
		}
		refreshToken = resp.RefreshToken
	})

	t.Run("confirm rejects an unknown token", func(t *testing.T) {
		if _, err := auth.EmailChangeConfirm(ctx, "not-a-real-token"); err != ErrInvalidOrExpiredEmailChangeToken {
			t.Fatalf("expected ErrInvalidOrExpiredEmailChangeToken, got %v", err)
		}
	})

	t.Run("confirm applies the change and revokes other sessions", func(t *testing.T) {
		updated, err := auth.EmailChangeConfirm(ctx, tokenValue)
		if err != nil {
			t.Fatalf("EmailChangeConfirm failed: %v", err)
		}
		if updated.Email != newEmail || !updated.EmailVerified {
			t.Fatalf("unexpected user after confirm: %+v", updated)
		}

		if _, err := auth.Repo.UserGetByEmail(ctx, email); err == nil {
			t.Fatal("expected the old email to no longer resolve to the user")
		}

		tok, err := auth.Repo.TokenGetByToken(ctx, refreshToken)
		if err != nil {
			t.Fatalf("failed to get pre-existing refresh token: %v", err)
		}
		if !tok.Revoked {
			t.Fatal("expected pre-existing sessions to be revoked after email change")
		}
	})

	t.Run("confirm is single-use", func(t *testing.T) {
		if _, err := auth.EmailChangeConfirm(ctx, tokenValue); err != ErrInvalidOrExpiredEmailChangeToken {
			t.Fatalf("expected reused token to be rejected, got %v", err)
		}
	})
}
