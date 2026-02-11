package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
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
	xlog.Debug("passwordless login requested", "email", req.Email)
	// Find or create user
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		// User doesn't exist, create one to attach the token to
		xlog.Debug("creating temporary user for passwordless login", "email", req.Email)
		user = &models.User{
			Email:         req.Email,
			Provider:      "local",
			EmailVerified: false,
		}
		user, err = a.Repo.UserCreate(ctx, user)
		if err != nil {
			xlog.Error("failed to create temporary user", "email", req.Email, "err", err)
			return err
		}
	}

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate token", "err", err)
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
		xlog.Error("failed to save passwordless token", "user_id", user.ID, "err", err)
		return err
	}

	// Send email
	prefix := a.PathPrefix
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimSuffix(prefix, "/")
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

	if err := a.Mailer.Send(req.Email, subject, body); err != nil {
		xlog.Error("failed to send passwordless email", "email", req.Email, "err", err)
		return err
	}
	xlog.Info("passwordless login email sent", "email", req.Email)
	return nil
}

// PasswordlessLogin completes the passwordless login flow.
func (a *Auth) PasswordlessLogin(ctx context.Context, tokenValue string) (*TokenResponse, error) {
	xlog.Debug("processing passwordless login")
	token, err := a.Repo.TokenGetByToken(ctx, tokenValue)
	if err != nil {
		xlog.Debug("passwordless token not found", "err", err)
		return nil, errors.New("invalid or expired magic link")
	}

	if token.TokenType != models.TokenTypePasswordless {
		xlog.Warn("invalid token type for passwordless login", "type", token.TokenType)
		return nil, errors.New("invalid token type")
	}

	if time.Now().After(token.ExpiresAt) || token.Revoked {
		a.Repo.TokenRevoke(ctx, token.ID)
		xlog.Debug("passwordless token expired or revoked", "token_id", token.ID)
		return nil, errors.New("magic link expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		xlog.Error("failed to get user for passwordless login", "user_id", token.UserID, "err", err)
		return nil, err
	}

	if !user.EmailVerified {
		now := time.Now()
		user.EmailVerified = true
		user.EmailVerifiedAt = &now
		if _, err := a.Repo.UserUpdate(ctx, user); err != nil {
			xlog.Error("failed to update user email verification", "user_id", user.ID, "err", err)
			return nil, err
		}
	}

	// Consume token
	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke passwordless token", "token_id", token.ID, "err", err)
		return nil, err
	}

	// Create session
	resp, err := a.TokenCreate(ctx, user)
	if err != nil {
		return nil, err
	}
	xlog.Info("passwordless login successful", "user_id", user.ID)
	return resp, nil
}
