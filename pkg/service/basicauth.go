package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
	"golang.org/x/crypto/bcrypt"
)

// RequestBasicAuth defines the parameters for basic authentication (email/password).
type RequestBasicAuth struct {
	Email     string         `json:"email"`
	Password  string         `json:"password"`
	FirstName string         `json:"first_name"`
	LastName  string         `json:"last_name"`
	Locale    string         `json:"locale"`
	Timezone  string         `json:"timezone"`
	Roles     string         `json:"roles"`
	Data      map[string]any `json:"data"`
}

// RequestPasswordReset defines the parameters for requesting a password reset.
type RequestPasswordReset struct {
	Email string `json:"email"`
}

// RequestPasswordResetConfirm defines the parameters for confirming a password reset.
type RequestPasswordResetConfirm struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// UserCreate creates a new user with email and password.
func (a *Auth) UserCreate(ctx context.Context, req *RequestBasicAuth) (*models.User, error) {
	xlog.Debug("creating user", "email", req.Email)
	if err := a.validatePassword(req.Password); err != nil {
		xlog.Debug("password validation failed", "email", req.Email, "err", err)
		return nil, err
	}
	hash, err := a.UserHashPassword(req.Password)
	if err != nil {
		xlog.Error("failed to hash password", "email", req.Email, "err", err)
		return nil, err
	}
	user := &models.User{
		Email:        req.Email,
		PasswordHash: hash,
		UserMetadata: req.Data,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Locale:       req.Locale,
		Timezone:     req.Timezone,
		Roles:        req.Roles,
		Provider:     "local",
	}
	u, err := a.Repo.UserCreate(ctx, user)
	if err != nil {
		xlog.Error("failed to create user", "email", req.Email, "err", err)
		return nil, err
	}
	xlog.Info("user created", "id", u.ID, "email", u.Email)
	return u, nil
}

// UserHashPassword generates a bcrypt hash of the given password.
func (a Auth) UserHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (a Auth) validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	return nil
}

// UserAuthenticate authenticates a user with email and password.
func (a Auth) UserAuthenticate(ctx context.Context, req RequestBasicAuth) (*models.User, error) {
	xlog.Debug("authenticating user", "email", req.Email)
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		xlog.Debug("authentication failed: user not found", "email", req.Email, "err", err)
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		xlog.Debug("authentication failed: invalid credentials", "email", req.Email)
		return nil, errors.New("invalid credentials")
	}
	xlog.Info("user authenticated", "id", user.ID, "email", user.Email)
	return user, nil
}

// UserUpdatePassword updates the password for a user.
func (a Auth) UserUpdatePassword(ctx context.Context, user *models.User, password string) (*models.User, error) {
	if err := a.validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := a.UserHashPassword(password)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = hash
	return a.Repo.UserUpdate(ctx, user)
}

// UserUpdate updates the user information.
func (a Auth) UserUpdate(ctx context.Context, user *models.User) (*models.User, error) {
	return a.Repo.UserUpdate(ctx, user)
}

// UserDelete deletes a user by ID.
func (a Auth) UserDelete(ctx context.Context, id string) error {
	return a.Repo.UserDelete(ctx, id)
}

// PasswordResetRequest initiates the password reset flow.
func (a *Auth) PasswordResetRequest(ctx context.Context, req RequestPasswordReset) error {
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		// We don't want to leak if a user exists or not
		return nil
	}

	tokenValue, err := a.generateRefreshToken() // Reusing the same 32-byte hex generator
	if err != nil {
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     tokenValue,
		TokenType: models.TokenTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		Revoked:   false,
		Metadata:  models.JSONMap{},
	}

	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		return err
	}

	// Build reset link
	prefix := a.PathPrefix
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimSuffix(prefix, "/")
	}

	link := fmt.Sprintf("%s%s/password-reset/confirm?token=%s", a.Cfg.BaseURL, prefix, tokenValue)

	// Render email templates
	data := EmailTemplateData{
		Link:  link,
		Token: tokenValue,
		Email: user.Email,
	}
	subject := RenderTemplate(a.Cfg.EmailTemplates.PasswordResetSubject, data)
	body := RenderTemplate(a.Cfg.EmailTemplates.PasswordResetBody, data)

	return a.Mailer.Send(user.Email, subject, body)
}

// PasswordResetConfirm completes the password reset flow.
func (a *Auth) PasswordResetConfirm(ctx context.Context, req RequestPasswordResetConfirm) error {
	token, err := a.Repo.TokenGetByToken(ctx, req.Token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	if token.TokenType != models.TokenTypePasswordReset {
		return errors.New("invalid token type")
	}

	if token.Revoked {
		return errors.New("token already used")
	}

	if time.Now().After(token.ExpiresAt) {
		return errors.New("token expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		return err
	}

	// Update password
	if _, err := a.UserUpdatePassword(ctx, user, req.Password); err != nil {
		return err
	}

	// Revoke token
	return a.Repo.TokenRevoke(ctx, token.ID)
}
