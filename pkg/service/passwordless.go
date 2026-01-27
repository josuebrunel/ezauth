package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// RequestPasswordless defines the parameters for requesting a magic link.
type RequestPasswordless struct {
	Email string `json:"email"`
}

// RequestPasswordlessLogin defines the parameters for logging in with a magic link.
type RequestPasswordlessLogin struct {
	Token string `json:"token"`
}

// PasswordlessRequest initiates the passwordless (magic link) login flow.
func (a *Auth) PasswordlessRequest(ctx context.Context, req RequestPasswordless) error {
	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		return err
	}

	token := &models.PasswordlessToken{
		Email:     req.Email,
		Token:     tokenValue,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
	}

	if _, err := a.Repo.PasswordlessTokenCreate(ctx, token); err != nil {
		return err
	}

	// Send email
	subject := "Magic Link Login"
	body := fmt.Sprintf("Click the following link to login: %s/auth/passwordless/login?token=%s", a.Cfg.BaseURL, tokenValue)
	return a.Mailer.Send(req.Email, subject, body)
}

// PasswordlessLogin completes the passwordless login flow.
func (a *Auth) PasswordlessLogin(ctx context.Context, tokenValue string) (*TokenResponse, error) {
	token, err := a.Repo.PasswordlessTokenGetByToken(ctx, tokenValue)
	if err != nil {
		return nil, errors.New("invalid or expired magic link")
	}

	if time.Now().After(token.ExpiresAt) {
		a.Repo.PasswordlessTokenDelete(ctx, tokenValue)
		return nil, errors.New("magic link expired")
	}

	// Find or create user
	user, err := a.Repo.UserGetByEmail(ctx, token.Email)
	if err != nil {
		// User doesn't exist, create one
		user = &models.User{
			Email:         token.Email,
			Provider:      "local",
			EmailVerified: true,
		}
		user, err = a.Repo.UserCreate(ctx, user)
		if err != nil {
			return nil, err
		}
	}

	// Consume token
	if err := a.Repo.PasswordlessTokenDelete(ctx, tokenValue); err != nil {
		return nil, err
	}

	// Create session
	return a.TokenCreate(ctx, user)
}
