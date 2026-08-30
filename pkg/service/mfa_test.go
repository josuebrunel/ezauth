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

func setupMFATestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("mfa_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret:     "test-secret",
		MFAIssuer:     "EzAuthTest",
		TrustedDevice: config.TrustedDevice{TTL: 720 * time.Hour},
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return auth
}

func mfaTestUser(t *testing.T, auth *Auth, ctx context.Context) *models.User {
	t.Helper()
	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("mfauser"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}

func TestMFAEnrollAndConfirm(t *testing.T) {
	auth := setupMFATestDB(t)
	ctx := context.Background()
	user := mfaTestUser(t, auth, ctx)

	t.Run("enroll generates secret", func(t *testing.T) {
		resp, err := auth.MFAEnroll(ctx, user)
		if err != nil {
			t.Fatalf("MFAEnroll failed: %v", err)
		}
		if resp.Secret == "" || resp.OTPAuthURL == "" {
			t.Fatalf("expected non-empty secret and otpauth url, got %+v", resp)
		}
		if user.MfaEnabled {
			t.Fatal("expected MfaEnabled to remain false until confirmed")
		}
	})

	t.Run("confirm rejects invalid code", func(t *testing.T) {
		if _, err := auth.MFAConfirm(ctx, user, "000000"); err == nil {
			t.Fatal("expected error for invalid code")
		}
	})

	var recoveryCodes []string
	t.Run("confirm enables mfa with valid code", func(t *testing.T) {
		code, err := totp.GenerateCode(*user.MfaSecret, time.Now())
		if err != nil {
			t.Fatalf("failed to generate totp code: %v", err)
		}
		codes, err := auth.MFAConfirm(ctx, user, code)
		if err != nil {
			t.Fatalf("MFAConfirm failed: %v", err)
		}
		if len(codes) != mfaRecoveryCodeCount {
			t.Fatalf("expected %d recovery codes, got %d", mfaRecoveryCodeCount, len(codes))
		}
		if !user.MfaEnabled {
			t.Fatal("expected MfaEnabled to be true after confirm")
		}
		recoveryCodes = codes
	})

	t.Run("enroll fails once already enabled", func(t *testing.T) {
		if _, err := auth.MFAEnroll(ctx, user); err != ErrMFAAlreadyEnabled {
			t.Fatalf("expected ErrMFAAlreadyEnabled, got %v", err)
		}
	})

	t.Run("disable rejects invalid code", func(t *testing.T) {
		if err := auth.MFADisable(ctx, user, "000000"); err == nil {
			t.Fatal("expected error for invalid code")
		}
	})

	t.Run("disable succeeds with a recovery code and consumes it", func(t *testing.T) {
		code := recoveryCodes[0]
		if err := auth.MFADisable(ctx, user, code); err != nil {
			t.Fatalf("MFADisable failed: %v", err)
		}
		if user.MfaEnabled {
			t.Fatal("expected MfaEnabled to be false after disable")
		}
	})
}

func TestMFALoginStepUp(t *testing.T) {
	auth := setupMFATestDB(t)
	ctx := context.Background()
	user := mfaTestUser(t, auth, ctx)

	t.Run("no mfa: CompleteBasicLogin returns tokens directly", func(t *testing.T) {
		resp, err := auth.CompleteBasicLogin(ctx, user, "")
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}
		if resp.MFARequired || resp.TokenResponse == nil {
			t.Fatalf("expected direct tokens for non-mfa user, got %+v", resp)
		}
	})

	enrollResp, err := auth.MFAEnroll(ctx, user)
	if err != nil {
		t.Fatalf("MFAEnroll failed: %v", err)
	}
	code, err := totp.GenerateCode(enrollResp.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}
	recoveryCodes, err := auth.MFAConfirm(ctx, user, code)
	if err != nil {
		t.Fatalf("MFAConfirm failed: %v", err)
	}

	var mfaToken string
	t.Run("mfa enabled: CompleteBasicLogin issues a pre-auth token", func(t *testing.T) {
		resp, err := auth.CompleteBasicLogin(ctx, user, "")
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}
		if !resp.MFARequired || resp.MFAToken == "" || resp.TokenResponse != nil {
			t.Fatalf("expected mfa challenge, got %+v", resp)
		}
		mfaToken = resp.MFAToken
	})

	t.Run("login verify rejects wrong code", func(t *testing.T) {
		if _, _, _, err := auth.MFALoginVerify(ctx, mfaToken, "000000", false); err == nil {
			t.Fatal("expected error for wrong code")
		}
	})

	t.Run("login verify rejects unknown token", func(t *testing.T) {
		if _, _, _, err := auth.MFALoginVerify(ctx, "not-a-real-token", "000000", false); err != ErrInvalidOrExpiredMFAToken {
			t.Fatalf("expected ErrInvalidOrExpiredMFAToken, got %v", err)
		}
	})

	t.Run("login verify succeeds with valid totp code and consumes the token", func(t *testing.T) {
		validCode, err := totp.GenerateCode(*user.MfaSecret, time.Now())
		if err != nil {
			t.Fatalf("failed to generate totp code: %v", err)
		}
		gotUser, tokens, _, err := auth.MFALoginVerify(ctx, mfaToken, validCode, false)
		if err != nil {
			t.Fatalf("MFALoginVerify failed: %v", err)
		}
		if gotUser.ID != user.ID || tokens.AccessToken == "" {
			t.Fatalf("unexpected result: user=%+v tokens=%+v", gotUser, tokens)
		}

		if _, _, _, err := auth.MFALoginVerify(ctx, mfaToken, validCode, false); err != ErrInvalidOrExpiredMFAToken {
			t.Fatalf("expected pre-auth token to be single-use, got %v", err)
		}
	})

	t.Run("login verify accepts an unused recovery code exactly once", func(t *testing.T) {
		resp, err := auth.CompleteBasicLogin(ctx, user, "")
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}

		recoveryCode := recoveryCodes[1]
		if _, _, _, err := auth.MFALoginVerify(ctx, resp.MFAToken, recoveryCode, false); err != nil {
			t.Fatalf("MFALoginVerify with recovery code failed: %v", err)
		}

		resp2, err := auth.CompleteBasicLogin(ctx, user, "")
		if err != nil {
			t.Fatalf("CompleteBasicLogin failed: %v", err)
		}
		if _, _, _, err := auth.MFALoginVerify(ctx, resp2.MFAToken, recoveryCode, false); err == nil {
			t.Fatal("expected reused recovery code to be rejected")
		}
	})
}
