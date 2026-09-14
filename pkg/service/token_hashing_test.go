package service

import (
	"context"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/pquerna/otp/totp"
)

// assertStoredHashedNotPlaintext proves raw (a bearer-style token value the
// service just issued -- a refresh token, API key, password-reset link,
// ...) is not discoverable in the tokens table by its plaintext value, and
// that the row actually found via its SHA-256 hash (util.HashToken) is not
// storing raw itself. This is the property #133 closes: previously these
// were stored and looked up verbatim, so a DB-read compromise handed over
// directly usable credentials.
func assertStoredHashedNotPlaintext(t *testing.T, auth *Auth, raw string) {
	t.Helper()
	ctx := context.Background()

	if _, err := auth.Repo.TokenGetByToken(ctx, raw); err == nil {
		t.Fatal("raw token value was found by a direct plaintext lookup -- it's stored unhashed")
	}

	hashed := util.HashToken(raw)
	tok, err := auth.Repo.TokenGetByToken(ctx, hashed)
	if err != nil {
		t.Fatalf("expected the token to be found by its SHA-256 hash, got: %v", err)
	}
	if tok.Token == raw {
		t.Fatal("stored Token field equals the raw value -- not actually hashed")
	}
	if tok.Token != hashed {
		t.Fatalf("stored Token field %q doesn't match the expected hash %q", tok.Token, hashed)
	}
}

func TestBearerTokensAreStoredHashed(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("hashcheck"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	mockMailer := auth.Mailer.(*MockMailer)

	lastEmailedToken := func() string {
		body := mockMailer.SentEmails[len(mockMailer.SentEmails)-1]["body"]
		return body[len(body)-64:] // generateRefreshToken() is a 32-byte hex string
	}

	t.Run("refresh token", func(t *testing.T) {
		resp, err := auth.TokenCreate(ctx, user)
		if err != nil {
			t.Fatalf("TokenCreate failed: %v", err)
		}
		assertStoredHashedNotPlaintext(t, auth, resp.RefreshToken)
	})

	t.Run("api key", func(t *testing.T) {
		tok, err := auth.APIKeyCreate(ctx, user.ID, nil)
		if err != nil {
			t.Fatalf("APIKeyCreate failed: %v", err)
		}
		if tok.Token == "" {
			t.Fatal("expected APIKeyCreate to still return the raw key value to the caller")
		}
		assertStoredHashedNotPlaintext(t, auth, tok.Token)
	})

	t.Run("password reset token", func(t *testing.T) {
		if err := auth.PasswordResetRequest(ctx, RequestPasswordReset{Email: user.Email}); err != nil {
			t.Fatalf("PasswordResetRequest failed: %v", err)
		}
		assertStoredHashedNotPlaintext(t, auth, lastEmailedToken())
	})

	t.Run("passwordless token", func(t *testing.T) {
		if err := auth.PasswordlessRequest(ctx, RequestPasswordless{Email: util.UniqueEmail("passwordless-hashcheck")}); err != nil {
			t.Fatalf("PasswordlessRequest failed: %v", err)
		}
		assertStoredHashedNotPlaintext(t, auth, lastEmailedToken())
	})

	t.Run("trusted device token", func(t *testing.T) {
		deviceToken, err := auth.TrustDevice(ctx, user, "test device")
		if err != nil {
			t.Fatalf("TrustDevice failed: %v", err)
		}
		assertStoredHashedNotPlaintext(t, auth, deviceToken)
	})
}

func TestMFAPreAuthTokenIsStoredHashed(t *testing.T) {
	auth := setupMFATestDB(t)
	ctx := context.Background()
	user := mfaTestUser(t, auth, ctx)

	enrollResp, err := auth.MFAEnroll(ctx, user)
	if err != nil {
		t.Fatalf("MFAEnroll failed: %v", err)
	}
	code, err := totp.GenerateCode(enrollResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}
	if _, err := auth.MFAConfirm(ctx, user, code); err != nil {
		t.Fatalf("MFAConfirm failed: %v", err)
	}

	resp, err := auth.CompleteBasicLogin(ctx, user, "")
	if err != nil {
		t.Fatalf("CompleteBasicLogin failed: %v", err)
	}
	if !resp.MFARequired || resp.MFAToken == "" {
		t.Fatalf("expected an MFA challenge with a pre-auth token, got %+v", resp)
	}

	assertStoredHashedNotPlaintext(t, auth, resp.MFAToken)
}

func TestInvitationTokenIsStoredHashed(t *testing.T) {
	auth := setupInvitationTestDB(t)
	ctx := context.Background()

	inviter, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("hashcheck-inviter"), Provider: "local"})
	if err != nil {
		t.Fatalf("failed to create inviter: %v", err)
	}

	if _, err := auth.InvitationCreate(ctx, inviter, RequestInvitation{Email: util.UniqueEmail("hashcheck-invitee")}); err != nil {
		t.Fatalf("InvitationCreate failed: %v", err)
	}

	mockMailer := auth.Mailer.(*MockMailer)
	body := mockMailer.SentEmails[len(mockMailer.SentEmails)-1]["body"]
	tokenValue := body[len(body)-64:]

	assertStoredHashedNotPlaintext(t, auth, tokenValue)
}

func TestEmailChangeTokenIsStoredHashed(t *testing.T) {
	dialect, dsn := util.GetTestDBConfig("email_change_hashcheck_test")
	cfg := &config.Config{
		DB:        config.Database{Dialect: dialect, DSN: dsn},
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4},
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
	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	ctx := context.Background()
	password := "securepass123"
	hash, err := auth.UserHashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("hashcheck-emailchange"),
		PasswordHash: hash,
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	if err := auth.EmailChangeRequest(ctx, user, RequestEmailChange{
		CurrentPassword: password,
		NewEmail:        util.UniqueEmail("hashcheck-newemail"),
	}); err != nil {
		t.Fatalf("EmailChangeRequest failed: %v", err)
	}

	mockMailer := auth.Mailer.(*MockMailer)
	// The verification email (to the new address) is sent first; the notice
	// to the old address second -- the token is only in the first.
	body := mockMailer.SentEmails[0]["body"]
	tokenValue := body[len(body)-64:]

	assertStoredHashedNotPlaintext(t, auth, tokenValue)
}
