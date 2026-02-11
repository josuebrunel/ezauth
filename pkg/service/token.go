package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

// TokenResponse defines the structure of the token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// TokenCreate creates a new pair of access and refresh tokens for the given user.
func (a *Auth) TokenCreate(ctx context.Context, user *models.User) (*TokenResponse, error) {
	xlog.Debug("creating tokens", "user_id", user.ID)
	accessToken, exp, err := a.generateAccessToken(user)
	if err != nil {
		xlog.Error("failed to generate access token", "user_id", user.ID, "err", err)
		return nil, err
	}

	refreshToken, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate refresh token", "user_id", user.ID, "err", err)
		return nil, err
	}

	now := time.Now()
	token := &models.Token{
		UserID:    user.ID,
		Token:     refreshToken,
		TokenType: models.TokenTypeRefresh,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		CreatedAt: now,
		Revoked:   false,
		Metadata:  models.JSONMap{},
	}

	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		xlog.Error("failed to save refresh token", "user_id", user.ID, "err", err)
		return nil, err
	}

	xlog.Debug("tokens created", "user_id", user.ID)
	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Until(exp).Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// TokenRefresh refreshes the access and refresh tokens using a valid refresh token.
func (a *Auth) TokenRefresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	xlog.Debug("refreshing token")
	token, err := a.Repo.TokenGetByToken(ctx, refreshToken)
	if err != nil {
		xlog.Debug("refresh token not found", "err", err)
		return nil, errors.New("invalid refresh token")
	}

	if token.Revoked {
		xlog.Warn("attempt to use revoked token", "token_id", token.ID, "user_id", token.UserID)
		return nil, errors.New("token revoked")
	}

	if time.Now().After(token.ExpiresAt) {
		xlog.Debug("refresh token expired", "token_id", token.ID, "user_id", token.UserID)
		return nil, errors.New("token expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		xlog.Error("failed to get user for refresh token", "user_id", token.UserID, "err", err)
		return nil, err
	}

	// Revoke old token
	if err := a.Repo.TokenRevoke(ctx, token.ID); err != nil {
		xlog.Error("failed to revoke old refresh token", "token_id", token.ID, "err", err)
		return nil, err
	}

	// Create new tokens
	return a.TokenCreate(ctx, user)
}

// TokenRevoke revokes the given refresh token.
func (a *Auth) TokenRevoke(ctx context.Context, refreshToken string) error {
	xlog.Info("revoking token")
	token, err := a.Repo.TokenGetByToken(ctx, refreshToken)
	if err != nil {
		xlog.Debug("token to revoke not found", "err", err)
		return err
	}
	err = a.Repo.TokenRevoke(ctx, token.ID)
	if err != nil {
		xlog.Error("failed to revoke token", "token_id", token.ID, "err", err)
	} else {
		xlog.Info("token revoked", "token_id", token.ID)
	}
	return err
}

func (a *Auth) generateAccessToken(user *models.User) (string, time.Time, error) {
	exp := time.Now().Add(1 * time.Hour)
	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"exp":   jwt.NewNumericDate(exp),
		"iat":   jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(a.Cfg.JWTSecret))
	return t, exp, err
}

func (a *Auth) generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
