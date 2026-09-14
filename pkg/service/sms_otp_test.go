package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func uniqueTestPhone() string {
	return fmt.Sprintf("+1%010d", time.Now().UnixNano()%10000000000)
}

func setupSMSTestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("sms_otp_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
		SMSTemplates: config.SMSTemplates{
			OTPBody: "Your verification code is: {{.Code}}",
		},
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

func TestSMSOTP(t *testing.T) {
	auth := setupSMSTestDB(t)
	ctx := context.Background()
	phone := uniqueTestPhone()

	t.Run("rejects invalid phone", func(t *testing.T) {
		if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: "not-a-phone"}); err != ErrInvalidPhone {
			t.Fatalf("expected ErrInvalidPhone, got %v", err)
		}
	})

	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != nil {
		t.Fatalf("SMSOTPRequest failed: %v", err)
	}

	mockSMS, ok := auth.SMS.(*MockSMSSender)
	if !ok {
		t.Fatalf("expected MockSMSSender, got %T", auth.SMS)
	}
	if len(mockSMS.SentMessages) != 1 {
		t.Fatalf("expected 1 sms sent, got %d", len(mockSMS.SentMessages))
	}
	body := mockSMS.SentMessages[0]["body"]
	code := body[len(body)-6:]

	t.Run("rejects wrong code", func(t *testing.T) {
		if _, err := auth.SMSOTPVerify(ctx, RequestSMSOTPVerify{Phone: phone, Code: "000001"}); err != ErrInvalidOrExpiredSMSCode {
			t.Fatalf("expected ErrInvalidOrExpiredSMSCode, got %v", err)
		}
	})

	t.Run("verifies with correct code and logs in", func(t *testing.T) {
		resp, err := auth.SMSOTPVerify(ctx, RequestSMSOTPVerify{Phone: phone, Code: code})
		if err != nil {
			t.Fatalf("SMSOTPVerify failed: %v", err)
		}
		if resp.AccessToken == "" {
			t.Fatal("expected access token")
		}

		user, err := auth.Repo.UserGetByPhone(ctx, phone)
		if err != nil {
			t.Fatalf("failed to get user by phone: %v", err)
		}
		if !user.PhoneVerified {
			t.Error("expected phone to be verified after successful otp login")
		}
	})

	t.Run("code is single-use", func(t *testing.T) {
		if _, err := auth.SMSOTPVerify(ctx, RequestSMSOTPVerify{Phone: phone, Code: code}); err != ErrInvalidOrExpiredSMSCode {
			t.Fatalf("expected reused code to be rejected, got %v", err)
		}
	})
}

// TestSMSOTPRequest_RevokesPreviousCodeOnResend proves requesting a new
// code invalidates any still-live earlier code for the same phone number,
// so at most one code is ever valid at a time.
func TestSMSOTPRequest_RevokesPreviousCodeOnResend(t *testing.T) {
	old := otpResendCooldown
	otpResendCooldown = 0 // this test resends immediately; see TestSMSOTPRequest_EnforcesResendCooldown for the cooldown itself
	defer func() { otpResendCooldown = old }()

	auth := setupSMSTestDB(t)
	ctx := context.Background()
	phone := uniqueTestPhone()

	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != nil {
		t.Fatalf("first SMSOTPRequest failed: %v", err)
	}
	mockSMS, ok := auth.SMS.(*MockSMSSender)
	if !ok {
		t.Fatalf("expected MockSMSSender, got %T", auth.SMS)
	}
	firstBody := mockSMS.SentMessages[0]["body"]
	firstCode := firstBody[len(firstBody)-6:]

	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != nil {
		t.Fatalf("second SMSOTPRequest failed: %v", err)
	}
	secondBody := mockSMS.SentMessages[1]["body"]
	secondCode := secondBody[len(secondBody)-6:]

	if _, err := auth.SMSOTPVerify(ctx, RequestSMSOTPVerify{Phone: phone, Code: firstCode}); err != ErrInvalidOrExpiredSMSCode {
		t.Fatalf("expected the first (now superseded) code to be rejected, got %v", err)
	}

	if _, err := auth.SMSOTPVerify(ctx, RequestSMSOTPVerify{Phone: phone, Code: secondCode}); err != nil {
		t.Fatalf("expected the second (current) code to succeed, got %v", err)
	}
}

// TestSMSOTPRequest_EnforcesResendCooldown proves a second request for the
// same phone number within otpResendCooldown is rejected rather than
// sending another billable SMS -- a per-phone throttle independent of the
// general-purpose IP rate limiter, since a caller spreading requests across
// many source IPs could otherwise SMS-bomb a single target regardless of
// any per-IP limit.
func TestSMSOTPRequest_EnforcesResendCooldown(t *testing.T) {
	auth := setupSMSTestDB(t)
	ctx := context.Background()
	phone := uniqueTestPhone()

	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != nil {
		t.Fatalf("first SMSOTPRequest failed: %v", err)
	}
	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != ErrResendTooSoon {
		t.Fatalf("expected ErrResendTooSoon for an immediate resend, got %v", err)
	}

	mockSMS := auth.SMS.(*MockSMSSender)
	if len(mockSMS.SentMessages) != 1 {
		t.Fatalf("expected only 1 sms sent (the throttled resend must not send another), got %d", len(mockSMS.SentMessages))
	}

	otpResendCooldown = 0
	defer func() { otpResendCooldown = 60 * time.Second }()
	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != nil {
		t.Fatalf("expected a resend to succeed once the cooldown has passed, got %v", err)
	}
	if len(mockSMS.SentMessages) != 2 {
		t.Fatalf("expected 2 sms sent after the cooldown passed, got %d", len(mockSMS.SentMessages))
	}
}

// TestSMSOTPRequest_CodeNotDerivableFromStoredToken proves the persisted
// Token.Token value has no relationship to the OTP code -- unlike the old
// sha256(phone+code) scheme, a DB-read compromise can't derive the valid
// code offline from Token.Token, and the code's own hash (Metadata
// "code_hash") uses the same deliberately slow algorithm as real passwords.
func TestSMSOTPRequest_CodeNotDerivableFromStoredToken(t *testing.T) {
	auth := setupSMSTestDB(t)
	ctx := context.Background()
	phone := uniqueTestPhone()

	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != nil {
		t.Fatalf("SMSOTPRequest failed: %v", err)
	}
	mockSMS := auth.SMS.(*MockSMSSender)
	body := mockSMS.SentMessages[0]["body"]
	code := body[len(body)-6:]

	user, err := auth.Repo.UserGetByPhone(ctx, phone)
	if err != nil {
		t.Fatalf("UserGetByPhone failed: %v", err)
	}
	tokens, err := auth.Repo.TokenListByUserIDAndType(ctx, user.ID, models.TokenTypeSMSOTP)
	if err != nil {
		t.Fatalf("TokenListByUserIDAndType failed: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected exactly 1 live sms otp token, got %d", len(tokens))
	}
	tok := tokens[0]

	if tok.Token == util.HashToken(phone+":"+code) {
		t.Fatal("Token.Token must not be derivable from phone+code (the old, low-entropy scheme)")
	}
	codeHash, _ := tok.Metadata["code_hash"].(string)
	if codeHash == "" {
		t.Fatal("expected Metadata[\"code_hash\"] to be set")
	}
	if !strings.HasPrefix(codeHash, "$2a$") && !strings.HasPrefix(codeHash, "$2b$") && !strings.HasPrefix(codeHash, "$argon2id$") {
		t.Errorf("expected code_hash to use a deliberately slow password-hashing scheme, got %q", codeHash)
	}
}

// TestSMSOTPVerify_BruteForceLockout proves repeated wrong OTP guesses
// against a phone number lock the account, instead of being limited only by
// the (optional, off by default) global rate limiter.
func TestSMSOTPVerify_BruteForceLockout(t *testing.T) {
	dialect, dsn := util.GetTestDBConfig("sms_otp_lockout_test")
	cfg := &config.Config{
		DB:        config.Database{Dialect: dialect, DSN: dsn},
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4},
		SMSTemplates: config.SMSTemplates{
			OTPBody: "Your verification code is: {{.Code}}",
		},
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
	phone := uniqueTestPhone()
	if err := auth.SMSOTPRequest(ctx, RequestSMSOTP{Phone: phone}); err != nil {
		t.Fatalf("SMSOTPRequest failed: %v", err)
	}

	mockSMS := auth.SMS.(*MockSMSSender)
	body := mockSMS.SentMessages[0]["body"]
	code := body[len(body)-6:]
	wrongCode := "000000"
	if wrongCode == code {
		wrongCode = "111111"
	}

	// MaxAttempts wrong guesses against the same phone number lock the account.
	for i := 0; i < 3; i++ {
		if _, err := auth.SMSOTPVerify(ctx, RequestSMSOTPVerify{Phone: phone, Code: wrongCode}); err != ErrInvalidOrExpiredSMSCode {
			t.Fatalf("expected ErrInvalidOrExpiredSMSCode, got %v", err)
		}
	}

	user, err := auth.Repo.UserGetByPhone(ctx, phone)
	if err != nil {
		t.Fatalf("failed to get user by phone: %v", err)
	}
	if user.IsActive || user.LockedUntil == nil {
		t.Fatalf("expected account locked after 3 wrong otp guesses, got IsActive=%v lockedUntil=%v", user.IsActive, user.LockedUntil)
	}

	// Even the correct (still-valid, unexpired) code is now rejected, since
	// the account itself is locked.
	if _, err := auth.SMSOTPVerify(ctx, RequestSMSOTPVerify{Phone: phone, Code: code}); err != ErrAccountLocked {
		t.Fatalf("expected ErrAccountLocked even with the correct code once locked, got %v", err)
	}
}

func TestUserPhoneUniqueness(t *testing.T) {
	auth := setupSMSTestDB(t)
	ctx := context.Background()
	phone := uniqueTestPhone()

	if _, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("phoneowner1"), Phone: phone, Provider: "local"}); err != nil {
		t.Fatalf("failed to create first user: %v", err)
	}

	if _, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("phoneowner2"), Phone: phone, Provider: "local"}); err == nil {
		t.Fatal("expected duplicate phone number to be rejected")
	}
}
