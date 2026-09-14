package middleware

import (
	"context"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// TokenGetter defines the interface for retrieving tokens.
type TokenGetter interface {
	TokenGetByToken(ctx context.Context, token string) (*models.Token, error)
}

// UserGetter defines the interface for retrieving users.
type UserGetter interface {
	UserGetByID(ctx context.Context, id string) (*models.User, error)
	GetSessionTokens(ctx context.Context) (map[string]string, bool)
}

// UserActiveGetter is the minimal interface AuthMiddleware and
// APIKeyMiddleware use to re-check the owning user's status on every
// request, rather than trusting a Bearer token's claims or an API key's own
// revoked/expiry fields to still reflect the account's current state for the
// credential's whole remaining lifetime.
type UserActiveGetter interface {
	UserGetByID(ctx context.Context, id string) (*models.User, error)
}

// AuthChecker defines the interface for checking authentication status.
type AuthChecker interface {
	IsAuthenticated(ctx context.Context) bool
}
