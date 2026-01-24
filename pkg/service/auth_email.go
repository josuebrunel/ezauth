package service

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// EmailPasswordCredential holds login data
type EmailPasswordCredential struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"` // For sign up
}

// SignUp registers a new user with email and password
func (a *Auth) SignUp(ctx context.Context, creds EmailPasswordCredential) (*User, error) {
	if creds.Email == "" || creds.Password == "" {
		return nil, errors.New("email and password are required")
	}

	// Check if user exists
	existingUser, err := a.Config.Storage.GetUserByEmail(ctx, creds.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, errors.New("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	newUser := &User{
		ID:            GenerateID(),
		Email:         creds.Email,
		Name:          creds.Name,
		EmailVerified: false,
		Password:      string(hashedPassword),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	return a.Config.Storage.CreateUser(ctx, newUser)
}

// SignIn authenticates a user
func (a *Auth) SignIn(ctx context.Context, creds EmailPasswordCredential) (*Session, error) {
	user, err := a.Config.Storage.GetUserByEmail(ctx, creds.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Verify password
	if user.Password == "" {
		return nil, errors.New("invalid credentials") // User might have signed up with OAuth
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Create Session
	session := &Session{
		ID:        GenerateID(),
		UserID:    user.ID,
		Token:     GenerateToken(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 days default
		CreatedAt: time.Now(),
	}

	return a.Config.Storage.CreateSession(ctx, session)
}
