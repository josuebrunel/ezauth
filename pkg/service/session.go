package service

import (
	"context"
	"errors"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

// ErrSessionNotFound is returned when a session record doesn't exist, doesn't
// belong to the caller, or isn't a refresh-token session.
var ErrSessionNotFound = errors.New("session not found")

// SessionInfo describes one of a user's active (non-revoked) refresh-token
// sessions without exposing the raw token value.
type SessionInfo struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Sessions lists the active refresh-token sessions for a user, most recent
// first — each one corresponds to a device/client that is currently logged in.
func (a *Auth) Sessions(ctx context.Context, userID string) ([]SessionInfo, error) {
	tokens, err := a.Repo.TokenListByUserIDAndType(ctx, userID, models.TokenTypeRefresh)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, 0, len(tokens))
	for _, tok := range tokens {
		sessions = append(sessions, SessionInfo{
			ID:        tok.ID,
			CreatedAt: tok.CreatedAt,
			ExpiresAt: tok.ExpiresAt,
		})
	}
	return sessions, nil
}

// RevokeSession revokes one of user's active sessions by its record ID (as
// returned by Sessions), logging that device out immediately.
func (a *Auth) RevokeSession(ctx context.Context, user *models.User, sessionID string) error {
	tok, err := a.Repo.TokenGetByID(ctx, sessionID)
	if err != nil || tok.UserID != user.ID || tok.TokenType != models.TokenTypeRefresh {
		return ErrSessionNotFound
	}
	if err := a.Repo.TokenRevoke(ctx, tok.ID); err != nil {
		xlog.Error("failed to revoke session", "user_id", user.ID, "session_id", tok.ID, "err", err)
		return err
	}
	xlog.Info("session revoked", "user_id", user.ID, "session_id", tok.ID)
	return nil
}

// RevokeAllSessions revokes all of user's active sessions except, if
// non-empty, the one whose record ID matches exceptSessionID (e.g. the
// caller's own current session) — "log out other devices". Pass an empty
// exceptSessionID to log the user out everywhere.
func (a *Auth) RevokeAllSessions(ctx context.Context, user *models.User, exceptSessionID string) error {
	tokens, err := a.Repo.TokenListByUserIDAndType(ctx, user.ID, models.TokenTypeRefresh)
	if err != nil {
		return err
	}

	for _, tok := range tokens {
		if tok.ID == exceptSessionID {
			continue
		}
		if err := a.Repo.TokenRevoke(ctx, tok.ID); err != nil {
			xlog.Error("failed to revoke session", "user_id", user.ID, "session_id", tok.ID, "err", err)
			return err
		}
	}
	xlog.Info("all sessions revoked", "user_id", user.ID, "except_session_id", exceptSessionID)
	return nil
}
