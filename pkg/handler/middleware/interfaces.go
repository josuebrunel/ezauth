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

// AuthChecker defines the interface for checking authentication status.
type AuthChecker interface {
	IsAuthenticated(ctx context.Context) bool
}
