package service

import (
	"time"
)

// User represents the authenticated user
type User struct {
	ID            string    `json:"id"`
	Name          string    `json:"name,omitempty"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Password      string    `json:"-"`
	Image         string    `json:"image,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// Session represents a user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"userAgent,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// Account represents a linked OAuth account
type Account struct {
	ID                string    `json:"id"`
	UserID            string    `json:"userId"`
	Provider          string    `json:"provider"`
	ProviderAccountID string    `json:"providerAccountId"`
	RefreshToken      string    `json:"refreshToken,omitempty"`
	AccessToken       string    `json:"accessToken,omitempty"`
	ExpiresAt         time.Time `json:"expiresAt,omitempty"`
	TokenType         string    `json:"tokenType,omitempty"`
	Scope             string    `json:"scope,omitempty"`
	IDToken           string    `json:"idToken,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// VerificationToken is used for email verification, password reset, etc.
type VerificationToken struct {
	Identifier string    `json:"identifier"` // e.g., email or random ID
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expiresAt"`
	CreatedAt  time.Time `json:"createdAt"`
}

// Config holds the configuration for the EzAuth library
type Config struct {
	Storage   StorageAdapter
	Mailer    Mailer
	Providers []OAuthProvider
	// Debug enables debug logging
	Debug bool
}
