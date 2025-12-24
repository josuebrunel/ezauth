package service

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// ValidateSession checks if a session token is valid and returns the session
func (a *Auth) ValidateSession(ctx context.Context, token string) (*Session, error) {
	session, err := a.Config.Storage.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrInvalidToken
	}

	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session?
		_ = a.Config.Storage.DeleteSession(ctx, token)
		return nil, ErrInvalidToken
	}

	return session, nil
}

// RevokeSession deletes a session
func (a *Auth) RevokeSession(ctx context.Context, token string) error {
	return a.Config.Storage.DeleteSession(ctx, token)
}

// Helper to extract token from request (Bearer or Cookie)
func (a *Auth) GetTokenFromRequest(r *http.Request) string {
	// 1. Check Authorization header
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// 2. Check Cookie
	if cookie, err := r.Cookie("session_token"); err == nil {
		return cookie.Value
	}

	return ""
}
