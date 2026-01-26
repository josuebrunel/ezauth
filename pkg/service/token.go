package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (a *Auth) TokenCreate(ctx context.Context, user *models.User) (*TokenResponse, error) {
	accessToken, exp, err := a.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := a.generateRefreshToken()
	if err != nil {
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
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Until(exp).Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (a *Auth) TokenRefresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	token, err := a.Repo.TokenGetByToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	if token.Revoked {
		return nil, errors.New("token revoked")
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, errors.New("token expired")
	}

	user, err := a.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	accessToken, exp, err := a.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(time.Until(exp).Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (a *Auth) TokenRevoke(ctx context.Context, refreshToken string) error {
	token, err := a.Repo.TokenGetByToken(ctx, refreshToken)
	if err != nil {
		return err
	}
	return a.Repo.TokenRevoke(ctx, token.ID)
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
