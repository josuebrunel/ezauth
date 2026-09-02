package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func sessionTestUser(t *testing.T, auth *Auth, ctx context.Context) *models.User {
	t.Helper()
	user := &models.User{
		Email:        util.UniqueEmail("session"),
		PasswordHash: "some-hash",
		Provider:     "local",
	}
	created, err := auth.Repo.UserCreate(ctx, user)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return created
}

func TestSessions(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()
	user := sessionTestUser(t, auth, ctx)

	t.Run("no sessions before login", func(t *testing.T) {
		sessions, err := auth.Sessions(ctx, user.ID)
		if err != nil {
			t.Fatalf("Sessions failed: %v", err)
		}
		if len(sessions) != 0 {
			t.Fatalf("expected 0 sessions, got %d", len(sessions))
		}
	})

	var sessionIDs []string
	t.Run("each TokenCreate shows up as a session", func(t *testing.T) {
		for range 3 {
			if _, err := auth.TokenCreate(ctx, user); err != nil {
				t.Fatalf("TokenCreate failed: %v", err)
			}
		}
		sessions, err := auth.Sessions(ctx, user.ID)
		if err != nil {
			t.Fatalf("Sessions failed: %v", err)
		}
		if len(sessions) != 3 {
			t.Fatalf("expected 3 sessions, got %d", len(sessions))
		}
		for _, s := range sessions {
			sessionIDs = append(sessionIDs, s.ID)
		}
	})

	t.Run("RevokeSession removes one session", func(t *testing.T) {
		if err := auth.RevokeSession(ctx, user, sessionIDs[0]); err != nil {
			t.Fatalf("RevokeSession failed: %v", err)
		}
		sessions, err := auth.Sessions(ctx, user.ID)
		if err != nil {
			t.Fatalf("Sessions failed: %v", err)
		}
		if len(sessions) != 2 {
			t.Fatalf("expected 2 sessions after revoke, got %d", len(sessions))
		}
	})

	t.Run("RevokeSession rejects another user's session", func(t *testing.T) {
		other := sessionTestUser(t, auth, ctx)
		if err := auth.RevokeSession(ctx, other, sessionIDs[1]); err != ErrSessionNotFound {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("RevokeSession rejects an unknown session id", func(t *testing.T) {
		if err := auth.RevokeSession(ctx, user, "not-a-real-session-id"); err != ErrSessionNotFound {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("RevokeAllSessions keeps the excepted session", func(t *testing.T) {
		sessions, err := auth.Sessions(ctx, user.ID)
		if err != nil {
			t.Fatalf("Sessions failed: %v", err)
		}
		keep := sessions[0].ID

		if err := auth.RevokeAllSessions(ctx, user, keep); err != nil {
			t.Fatalf("RevokeAllSessions failed: %v", err)
		}

		sessions, err = auth.Sessions(ctx, user.ID)
		if err != nil {
			t.Fatalf("Sessions failed: %v", err)
		}
		if len(sessions) != 1 || sessions[0].ID != keep {
			t.Fatalf("expected only session %q to remain, got %+v", keep, sessions)
		}
	})

	t.Run("RevokeAllSessions with no exception logs out everywhere", func(t *testing.T) {
		if err := auth.RevokeAllSessions(ctx, user, ""); err != nil {
			t.Fatalf("RevokeAllSessions failed: %v", err)
		}
		sessions, err := auth.Sessions(ctx, user.ID)
		if err != nil {
			t.Fatalf("Sessions failed: %v", err)
		}
		if len(sessions) != 0 {
			t.Fatalf("expected 0 sessions, got %d", len(sessions))
		}
	})
}
