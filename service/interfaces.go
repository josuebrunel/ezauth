package service

import (
	"context"
)

// StorageAdapter defines the interface for data persistence
type StorageAdapter interface {
	// User operations
	CreateUser(ctx context.Context, user *User) (*User, error)
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) (*User, error)
	DeleteUser(ctx context.Context, id string) error

	// Session operations
	CreateSession(ctx context.Context, session *Session) (*Session, error)
	GetSession(ctx context.Context, token string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) (*Session, error)
	DeleteSession(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID string) error

	// Account operations (for OAuth)
	CreateAccount(ctx context.Context, account *Account) (*Account, error)
	GetAccount(ctx context.Context, provider, providerAccountID string) (*Account, error)
	LinkAccount(ctx context.Context, account *Account) error

	// Verification Token operations
	CreateVerificationToken(ctx context.Context, token *VerificationToken) (*VerificationToken, error)
	GetVerificationToken(ctx context.Context, identifier, token string) (*VerificationToken, error)
	DeleteVerificationToken(ctx context.Context, identifier, token string) error
}

// Mailer defines the interface for sending emails
type Mailer interface {
	SendMail(ctx context.Context, to, subject, htmlBody string) error
}

// OAuthProvider defines the interface for OAuth providers
type OAuthProvider interface {
	Name() string
	GetAuthorizationURL(state string) string
	Exchange(ctx context.Context, code string) (*OAuthToken, error)
	GetUserInfo(ctx context.Context, token *OAuthToken) (*UserInfo, error)
}

type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

type UserInfo struct {
	ID    string
	Name  string
	Email string
	Image string
}
