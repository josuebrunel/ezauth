package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
)

const smsOTPTTL = 10 * time.Minute

var phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{6,14}$`)

var (
	ErrInvalidPhone            = errors.New("invalid phone number")
	ErrInvalidOrExpiredSMSCode = errors.New("invalid or expired code")
)

// RequestSMSOTP defines the parameters for requesting an SMS one-time code.
type RequestSMSOTP struct {
	Phone string `json:"phone"`
}

// RequestSMSOTPVerify defines the parameters for verifying an SMS one-time code.
type RequestSMSOTPVerify struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

// validatePhone rejects anything that isn't a plausible E.164-ish phone number.
// This is the only gate before a phone number is persisted and later used
// verbatim as an SMS recipient, so it must reject embedded CR/LF the same way
// validateEmail does for email, not just malformed numbers.
func validatePhone(phone string) error {
	if strings.ContainsAny(phone, "\r\n") {
		return ErrInvalidPhone
	}
	if !phoneRegex.MatchString(phone) {
		return ErrInvalidPhone
	}
	return nil
}

func generateSMSOTPCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// SMSOTPRequest initiates the SMS-based one-time-code login flow, mirroring
// PasswordlessRequest: an unrecognized phone number gets a temporary,
// unverified account, same as an unrecognized email does.
func (a *Auth) SMSOTPRequest(ctx context.Context, req RequestSMSOTP) error {
	phone := strings.TrimSpace(req.Phone)
	if err := validatePhone(phone); err != nil {
		return err
	}

	user, err := a.Repo.UserGetByPhone(ctx, phone)
	if err != nil {
		xlog.Debug("creating temporary user for sms otp login")
		user = &models.User{
			// ezauth_users.email is UNIQUE NOT NULL, so a phone-only signup
			// needs a synthetic placeholder rather than an empty string,
			// which would collide across every other phone-only account.
			// ".invalid" is the reserved RFC 2606 TLD for exactly this case.
			Email:    phone + "@phone.invalid",
			Phone:    phone,
			Provider: "local",
		}
		user, err = a.Repo.UserCreate(ctx, user)
		if err != nil {
			xlog.Error("failed to create temporary user for sms otp", "err", err)
			return err
		}
	}

	// Revoke any still-live code from an earlier request before issuing a
	// new one, so at most one code is ever valid for a phone number at a
	// time -- otherwise an older, still-unexpired code stays usable
	// alongside the new one.
	if err := a.Repo.TokenRevokeAllByUserIDAndType(ctx, user.ID, models.TokenTypeSMSOTP); err != nil {
		xlog.Warn("failed to revoke previous sms otp codes", "user_id", user.ID, "err", err)
	}

	code, err := generateSMSOTPCode()
	if err != nil {
		xlog.Error("failed to generate sms otp code", "err", err)
		return err
	}

	// The 6-digit code itself carries only ~20 bits of entropy, so it's
	// hashed with the same (deliberately slow, configurable-cost)
	// algorithm as real passwords rather than a fast hash like SHA-256 --
	// a DB-read compromise still can't derive the valid code by brute
	// force in any practical time, unlike a fast hash which making all
	// 10^6 candidates checkable in milliseconds. Token.Token itself is a
	// separate, high-entropy random value with no relationship to the
	// code, so it isn't a viable offline attack surface either; it exists
	// only to satisfy the column's NOT NULL UNIQUE constraint the same way
	// every other token type's does.
	codeHash, err := a.UserHashPassword(code)
	if err != nil {
		xlog.Error("failed to hash sms otp code", "err", err)
		return err
	}
	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate sms otp token", "err", err)
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     util.HashToken(tokenValue),
		TokenType: models.TokenTypeSMSOTP,
		ExpiresAt: time.Now().Add(smsOTPTTL),
		CreatedAt: time.Now(),
		Metadata:  models.JSONMap{"code_hash": codeHash},
	}
	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		xlog.Error("failed to save sms otp token", "user_id", user.ID, "err", err)
		return err
	}

	body := RenderTemplate(a.Cfg.SMSTemplates.OTPBody, SMSTemplateData{Code: code, Phone: phone})
	if err := a.SMS.Send(phone, body); err != nil {
		xlog.Error("failed to send sms otp", "user_id", user.ID, "err", err)
		return err
	}
	xlog.Info("sms otp sent", "user_id", user.ID)
	return nil
}

// SMSOTPVerify completes the SMS OTP login flow, mirroring PasswordlessLogin:
// a successful verification also marks the phone number verified.
//
// When Cfg.AccountLockout.Enabled, an invalid code counts against the same
// per-account failed-attempt counter and lockout as a wrong password
// (recordFailedLogin/checkAccountActive), so repeated code guessing against
// a phone number locks the account instead of being limited only by the
// (optional, IP-keyed) global rate limiter. The user is looked up by phone
// before the code is checked so a lockout can be attributed and enforced
// even though (unlike MFA's pre-auth token) nothing here identifies the
// account independently of a correct code guess.
func (a *Auth) SMSOTPVerify(ctx context.Context, req RequestSMSOTPVerify) (*TokenResponse, error) {
	phone := strings.TrimSpace(req.Phone)
	if err := validatePhone(phone); err != nil {
		return nil, err
	}
	if req.Code == "" {
		return nil, ErrInvalidOrExpiredSMSCode
	}

	byPhone, byPhoneErr := a.Repo.UserGetByPhone(ctx, phone)
	if byPhoneErr != nil {
		xlog.Debug("sms otp verify failed: no user for phone")
		return nil, ErrInvalidOrExpiredSMSCode
	}
	if a.Cfg.AccountLockout.Enabled {
		if _, err := a.checkAccountActive(ctx, byPhone); err != nil {
			xlog.Debug("sms otp verify failed: account locked", "user_id", byPhone.ID, "err", err)
			return nil, err
		}
	}

	// Codes are looked up by (user, type) rather than by a value derived
	// from the submitted code -- see SMSOTPRequest's comment on codeHash
	// for why -- so every still-live candidate (in practice at most one,
	// since SMSOTPRequest revokes prior codes on resend) is checked against
	// the submitted code with the same verifyPassword used for real
	// passwords.
	tokens, err := a.Repo.TokenListByUserIDAndType(ctx, byPhone.ID, models.TokenTypeSMSOTP)
	if err != nil {
		xlog.Error("failed to list sms otp tokens", "user_id", byPhone.ID, "err", err)
		return nil, err
	}

	var token *models.Token
	for _, candidate := range tokens {
		if time.Now().After(candidate.ExpiresAt) {
			continue
		}
		codeHash, _ := candidate.Metadata["code_hash"].(string)
		if codeHash != "" && verifyPassword(req.Code, codeHash) {
			token = candidate
			break
		}
	}

	if token == nil {
		xlog.Debug("sms otp code did not match")
		if a.Cfg.AccountLockout.Enabled {
			a.recordFailedLogin(ctx, byPhone)
		}
		return nil, ErrInvalidOrExpiredSMSCode
	}

	user := byPhone

	if user.FailedLoginAttempts > 0 {
		if reset, err := a.Repo.UserSetLockoutState(ctx, user.ID, 0, nil, true); err != nil {
			xlog.Warn("failed to reset failed login attempt counter after sms otp success", "user_id", user.ID, "err", err)
		} else {
			user = reset
		}
	}

	if !user.PhoneVerified {
		if _, err := a.Repo.UserSetPhoneVerified(ctx, user.ID, true); err != nil {
			xlog.Error("failed to update user phone verification", "user_id", user.ID, "err", err)
			return nil, err
		}
	}

	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke sms otp token", "token_id", token.ID, "err", err)
		return nil, err
	}

	resp, err := a.TokenCreate(ctx, user)
	if err != nil {
		return nil, err
	}
	xlog.Info("sms otp login successful", "user_id", user.ID)
	return resp, nil
}
