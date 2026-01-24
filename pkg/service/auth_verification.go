package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// SendVerificationEmail generates a token and sends a verification email
func (a *Auth) SendVerificationEmail(ctx context.Context, email string) error {
	token := GenerateToken()
	vToken := &VerificationToken{
		Identifier: email,
		Token:      token,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
	}

	_, err := a.Config.Storage.CreateVerificationToken(ctx, vToken)
	if err != nil {
		return err
	}

	// In a real app, we would construct a link like https://myapp.com/verify?token=...
	link := fmt.Sprintf("?token=%s&email=%s", token, email)

	if a.Config.Mailer != nil {
		return a.Config.Mailer.SendMail(ctx, email, "Verify your email", "Click here: "+link)
	}

	// If no mailer, maybe log it if debug?
	if a.Config.Debug {
		fmt.Printf("Verification Link: %s\n", link)
	}
	return nil
}

// VerifyEmail validates the token and updates the user
func (a *Auth) VerifyEmail(ctx context.Context, email, token string) error {
	vToken, err := a.Config.Storage.GetVerificationToken(ctx, email, token)
	if err != nil {
		return err
	}
	if vToken == nil {
		return errors.New("invalid or expired token")
	}

	user, err := a.Config.Storage.GetUserByEmail(ctx, email)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.EmailVerified = true
	_, err = a.Config.Storage.UpdateUser(ctx, user)
	if err != nil {
		return err
	}

	return a.Config.Storage.DeleteVerificationToken(ctx, email, token)
}

// GenerateOTP generates a numeric OTP
func GenerateOTP(length int) (string, error) {
	const digits = "0123456789"
	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		ret[i] = digits[num.Int64()]
	}
	return string(ret), nil
}

// SendOTP sends an OTP to the user's email
func (a *Auth) SendOTP(ctx context.Context, email string) error {
	otp, err := GenerateOTP(6)
	if err != nil {
		return err
	}

	vToken := &VerificationToken{
		Identifier: email,
		Token:      otp,
		ExpiresAt:  time.Now().Add(15 * time.Minute),
		CreatedAt:  time.Now(),
	}

	_, err = a.Config.Storage.CreateVerificationToken(ctx, vToken)
	if err != nil {
		return err
	}

	if a.Config.Mailer != nil {
		return a.Config.Mailer.SendMail(ctx, email, "Your OTP", "Code: "+otp)
	}
	if a.Config.Debug {
		fmt.Printf("OTP for %s: %s\n", email, otp)
	}
	return nil
}

// VerifyOTP checks the OTP
func (a *Auth) VerifyOTP(ctx context.Context, email, otp string) error {
	vToken, err := a.Config.Storage.GetVerificationToken(ctx, email, otp)
	if err != nil {
		return err
	}
	if vToken == nil {
		return errors.New("invalid or expired OTP")
	}

	// OTP verified. Usually we proceed to sign in or next step.
	// We delete it to prevent reuse
	return a.Config.Storage.DeleteVerificationToken(ctx, email, otp)
}

// SendMagicLink sends a passwordless login link
func (a *Auth) SendMagicLink(ctx context.Context, email string) error {
	// Reusing verification token mechanism, but purpose is login
	return a.SendVerificationEmail(ctx, email)
}

// VerifyMagicLink logs the user in with the token
func (a *Auth) VerifyMagicLink(ctx context.Context, email, token string) (*Session, error) {
	// 1. Verify Token
	vToken, err := a.Config.Storage.GetVerificationToken(ctx, email, token)
	if err != nil {
		return nil, err
	}
	if vToken == nil {
		return nil, errors.New("invalid or expired token")
	}

	// 2. Get or Create User
	user, err := a.Config.Storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if user == nil {
		// New user case for Magic Link
		newUser := &User{
			ID:            GenerateID(),
			Email:         email,
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}
		user, err = a.Config.Storage.CreateUser(ctx, newUser)
		if err != nil {
			return nil, err
		}
	} else {
		// Ensure email is verified if they used magic link
		if !user.EmailVerified {
			user.EmailVerified = true
			_, _ = a.Config.Storage.UpdateUser(ctx, user)
		}
	}

	// 3. Delete Token
	_ = a.Config.Storage.DeleteVerificationToken(ctx, email, token)

	// 4. Create Session
	session := &Session{
		ID:        GenerateID(),
		UserID:    user.ID,
		Token:     GenerateToken(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}

	return a.Config.Storage.CreateSession(ctx, session)
}
