package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
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

// smsOTPTokenValue derives the Token.Token lookup value for an SMS OTP code.
// Combining phone and code (rather than storing the 6-digit code alone) keeps
// the value globally unique despite the code's low entropy, and matches the
// existing pattern used for hashed MFA recovery codes.
func smsOTPTokenValue(phone, code string) string {
	sum := sha256.Sum256([]byte(phone + ":" + code))
	return hex.EncodeToString(sum[:])
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

	code, err := generateSMSOTPCode()
	if err != nil {
		xlog.Error("failed to generate sms otp code", "err", err)
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     smsOTPTokenValue(phone, code),
		TokenType: models.TokenTypeSMSOTP,
		ExpiresAt: time.Now().Add(smsOTPTTL),
		CreatedAt: time.Now(),
		Metadata:  models.JSONMap{},
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
func (a *Auth) SMSOTPVerify(ctx context.Context, req RequestSMSOTPVerify) (*TokenResponse, error) {
	phone := strings.TrimSpace(req.Phone)
	if err := validatePhone(phone); err != nil {
		return nil, err
	}
	if req.Code == "" {
		return nil, ErrInvalidOrExpiredSMSCode
	}

	token, err := a.Repo.TokenGetByToken(ctx, smsOTPTokenValue(phone, req.Code))
	if err != nil || token.TokenType != models.TokenTypeSMSOTP {
		xlog.Debug("sms otp token not found", "err", err)
		return nil, ErrInvalidOrExpiredSMSCode
	}

	if token.Revoked || time.Now().After(token.ExpiresAt) {
		xlog.Debug("sms otp token expired or revoked", "token_id", token.ID)
		return nil, ErrInvalidOrExpiredSMSCode
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		xlog.Error("failed to get user for sms otp login", "user_id", token.UserID, "err", err)
		return nil, err
	}

	if !user.PhoneVerified {
		user.PhoneVerified = true
		if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
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
