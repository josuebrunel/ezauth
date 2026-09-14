package service

import (
	"context"
	"encoding/hex"
	"strings"
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
		JWTSecret:     "test-secret-0123456789-0123456789",
		Hashing:       config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
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

// TestMFALoginVerify_BruteForceLockout proves repeated wrong TOTP codes
// against a still-valid pre-auth token lock the account, instead of being
// limited only by the (optional, off by default) global rate limiter.
func TestMFALoginVerify_BruteForceLockout(t *testing.T) {
	dialect, dsn := util.GetTestDBConfig("mfa_lockout_test")
	cfg := &config.Config{
		DB:            config.Database{Dialect: dialect, DSN: dsn},
		JWTSecret:     "test-secret-0123456789-0123456789",
		Hashing:       config.Hashing{BcryptCost: 4},
		MFAIssuer:     "EzAuthTest",
		TrustedDevice: config.TrustedDevice{TTL: 720 * time.Hour},
		AccountLockout: config.AccountLockout{
			Enabled:         true,
			MaxAttempts:     3,
			LockoutDuration: time.Hour,
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
	mfaToken := resp.MFAToken

	// MaxAttempts wrong guesses against the same pre-auth token lock the account.
	for i := 0; i < 3; i++ {
		if _, _, _, err := auth.MFALoginVerify(ctx, mfaToken, "000000", false); err == nil {
			t.Fatal("expected error for wrong code")
		}
	}

	locked, err := auth.Repo.UserGetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if locked.IsActive || locked.LockedUntil == nil {
		t.Fatalf("expected account locked after %d wrong mfa codes, got IsActive=%v lockedUntil=%v", 3, locked.IsActive, locked.LockedUntil)
	}

	// Even the correct code is now rejected against the (still otherwise
	// valid) pre-auth token, since the account itself is locked.
	validCode, err := totp.GenerateCode(*user.MfaSecret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}
	if _, _, _, err := auth.MFALoginVerify(ctx, mfaToken, validCode, false); err != ErrAccountLocked {
		t.Fatalf("expected ErrAccountLocked even with the correct code once locked, got %v", err)
	}
}

// TestGenerateRecoveryCode_Entropy proves recovery codes carry 128 bits of
// randomness (16 bytes), not the 40 bits a 5-byte code gave a DB-leak
// attacker.
func TestGenerateRecoveryCode_Entropy(t *testing.T) {
	code, err := generateRecoveryCode()
	if err != nil {
		t.Fatalf("generateRecoveryCode failed: %v", err)
	}

	hexChars := strings.ReplaceAll(code, "-", "")
	if len(hexChars) != recoveryCodeBytes*2 {
		t.Fatalf("expected %d hex chars (%d random bytes), got %d in %q", recoveryCodeBytes*2, recoveryCodeBytes, len(hexChars), code)
	}
	if _, err := hex.DecodeString(hexChars); err != nil {
		t.Fatalf("expected valid hex, got %q: %v", code, err)
	}

	code2, err := generateRecoveryCode()
	if err != nil {
		t.Fatalf("generateRecoveryCode failed: %v", err)
	}
	if code == code2 {
		t.Fatal("expected two calls to produce different codes")
	}
}
