package service

import (
	"context"
	"errors"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"golang.org/x/crypto/bcrypt"
)

type RequestBasicAuth struct {
	Email    string         `json:"email"`
	Password string         `json:"password"`
	Data     map[string]any `json:"data"`
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
