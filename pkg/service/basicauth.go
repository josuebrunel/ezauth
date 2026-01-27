package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"golang.org/x/crypto/bcrypt"
)

type RequestBasicAuth struct {
	Email    string         `json:"email"`
	Password string         `json:"password"`
	Data     map[string]any `json:"data"`
}

type RequestPasswordReset struct {
	Email string `json:"email"`
}

type RequestPasswordResetConfirm struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (a *Auth) UserCreate(ctx context.Context, req *RequestBasicAuth) (*models.User, error) {
	hash, err := a.UserHashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	user := &models.User{
		Email:        req.Email,
		PasswordHash: hash,
		UserMetadata: req.Data,
		Provider:     "local",
	}
	return a.Repo.UserCreate(ctx, user)
}

func (a Auth) UserHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (a Auth) UserAuthenticate(ctx context.Context, req RequestBasicAuth) (*models.User, error) {
	user, err := a.Repo.UserGetByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	return user, nil
}

func (a Auth) UserUpdatePassword(ctx context.Context, user *models.User, password string) (*models.User, error) {
	hash, err := a.UserHashPassword(password)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = hash
	return a.Repo.UserUpdate(ctx, user)
}

func (a Auth) UserUpdate(ctx context.Context, user *models.User) (*models.User, error) {
	return a.Repo.UserUpdate(ctx, user)
}

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

	// Send email
	subject := "Password Reset Request"
	body := fmt.Sprintf("You requested a password reset. Please use the following token: %s", tokenValue)
	return a.Mailer.Send(user.Email, subject, body)
}

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
