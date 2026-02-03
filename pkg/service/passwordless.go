package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	// Find or create user
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		// User doesn't exist, create one to attach the token to
		user = &models.User{
			Email:         req.Email,
			Provider:      "local",
			EmailVerified: false,
		}
		user, err = a.Repo.UserCreate(ctx, user)
		if err != nil {
			return err
		}
	}

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     tokenValue,
		TokenType: models.TokenTypePasswordless,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		CreatedAt: time.Now(),
	}

	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		return err
	}

	// Send email
	prefix := a.PathPrefix
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		if strings.HasSuffix(prefix, "/") {
			prefix = strings.TrimSuffix(prefix, "/")
		}
	}

	link := fmt.Sprintf("%s%s/passwordless/login?token=%s", a.Cfg.BaseURL, prefix, tokenValue)

	// Render email templates
	data := EmailTemplateData{
		Link:  link,
		Token: tokenValue,
		Email: req.Email,
	}
	subject := RenderTemplate(a.Cfg.EmailTemplates.PasswordlessSubject, data)
	body := RenderTemplate(a.Cfg.EmailTemplates.PasswordlessBody, data)

	return a.Mailer.Send(req.Email, subject, body)
}

// PasswordlessLogin completes the passwordless login flow.
func (a *Auth) PasswordlessLogin(ctx context.Context, tokenValue string) (*TokenResponse, error) {
	token, err := a.Repo.TokenGetByToken(ctx, tokenValue)
	if err != nil {
		return nil, errors.New("invalid or expired magic link")
	}

	if token.TokenType != models.TokenTypePasswordless {
		return nil, errors.New("invalid token type")
	}

	if time.Now().After(token.ExpiresAt) || token.Revoked {
		a.Repo.TokenRevoke(ctx, token.ID)
		return nil, errors.New("magic link expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	if !user.EmailVerified {
		now := time.Now()
		user.EmailVerified = true
		user.EmailVerifiedAt = &now
		if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
			return nil, err
		}
	}

	// Consume token
	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		return nil, err
	}

	// Create session
	return a.TokenCreate(ctx, user)
}
