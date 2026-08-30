package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func TestAdminUsersList(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	prefix := "adminlist" + util.NewIDStripped()[:8]
	var created []*models.User
	for i := 0; i < 3; i++ {
		u, err := auth.Repo.UserCreate(ctx, &models.User{
			Email:    fmt.Sprintf("%s_%d@test.com", prefix, i),
			Provider: "local",
		})
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}
		created = append(created, u)
	}

	t.Run("search finds only matching users", func(t *testing.T) {
		result, err := auth.UsersList(ctx, ListUsersOptions{Search: prefix})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(result.Users) != 3 {
			t.Fatalf("expected 3 matching users, got %d", len(result.Users))
		}
		for _, u := range result.Users {
			if u.PasswordHash != "" {
				t.Fatal("expected PasswordHash to be sanitized")
			}
		}
	})

	t.Run("pagination reports has_more", func(t *testing.T) {
		result, err := auth.UsersList(ctx, ListUsersOptions{Search: prefix, Limit: 2})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(result.Users) != 2 || !result.HasMore {
			t.Fatalf("expected a partial page with has_more, got %d users hasMore=%v", len(result.Users), result.HasMore)
		}

		result2, err := auth.UsersList(ctx, ListUsersOptions{Search: prefix, Limit: 2, Offset: 2})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(result2.Users) != 1 || result2.HasMore {
			t.Fatalf("expected the last remaining user with hasMore=false, got %d users hasMore=%v", len(result2.Users), result2.HasMore)
		}
	})

	t.Run("search is case-insensitive", func(t *testing.T) {
		result, err := auth.UsersList(ctx, ListUsersOptions{Search: strings.ToUpper(prefix)})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(result.Users) != 3 {
			t.Fatalf("expected case-insensitive search to match all 3 users, got %d", len(result.Users))
		}
	})

	t.Run("no match returns an empty page", func(t *testing.T) {
		result, err := auth.UsersList(ctx, ListUsersOptions{Search: "no-such-user-xyz"})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(result.Users) != 0 {
			t.Fatalf("expected no users, got %d", len(result.Users))
		}
	})

	t.Run("rejects an invalid status filter", func(t *testing.T) {
		if _, err := auth.UsersList(ctx, ListUsersOptions{Status: "bogus"}); err != ErrInvalidUserStatusFilter {
			t.Fatalf("expected ErrInvalidUserStatusFilter, got %v", err)
		}
	})

	t.Run("status filter distinguishes active/locked/suspended", func(t *testing.T) {
		active := created[0]
		locked := created[1]
		suspended := created[2]

		future := time.Now().Add(time.Hour)
		if _, err := auth.Repo.UserSetLockoutState(ctx, locked.ID, 3, &future, false); err != nil {
			t.Fatalf("failed to lock user: %v", err)
		}
		if _, err := auth.Repo.UserSetLockoutState(ctx, suspended.ID, 0, nil, false); err != nil {
			t.Fatalf("failed to suspend user: %v", err)
		}

		activeResult, err := auth.UsersList(ctx, ListUsersOptions{Search: prefix, Status: models.UserStatusActive})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(activeResult.Users) != 1 || activeResult.Users[0].ID != active.ID {
			t.Fatalf("expected only the active user, got %+v", activeResult.Users)
		}

		lockedResult, err := auth.UsersList(ctx, ListUsersOptions{Search: prefix, Status: models.UserStatusLocked})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(lockedResult.Users) != 1 || lockedResult.Users[0].ID != locked.ID {
			t.Fatalf("expected only the locked user, got %+v", lockedResult.Users)
		}

		suspendedResult, err := auth.UsersList(ctx, ListUsersOptions{Search: prefix, Status: models.UserStatusSuspended})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(suspendedResult.Users) != 1 || suspendedResult.Users[0].ID != suspended.ID {
			t.Fatalf("expected only the suspended user, got %+v", suspendedResult.Users)
		}
	})

	t.Run("created_after/created_before filter by registration time", func(t *testing.T) {
		farFuture := time.Now().Add(24 * time.Hour)
		result, err := auth.UsersList(ctx, ListUsersOptions{Search: prefix, CreatedAfter: &farFuture})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(result.Users) != 0 {
			t.Fatalf("expected no users created after a future timestamp, got %d", len(result.Users))
		}

		farPast := time.Now().Add(-24 * time.Hour)
		result, err = auth.UsersList(ctx, ListUsersOptions{Search: prefix, CreatedAfter: &farPast})
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(result.Users) != 3 {
			t.Fatalf("expected all 3 users created after a past timestamp, got %d", len(result.Users))
		}
	})
}

func TestAdminSuspendReactivate(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("adminsuspend")
	password := "securepass123"
	user, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password})
	if err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	t.Run("suspend disables login without an auto-expiry", func(t *testing.T) {
		suspended, err := auth.UserSuspend(ctx, user.ID)
		if err != nil {
			t.Fatalf("UserSuspend failed: %v", err)
		}
		if suspended.IsActive || suspended.LockedUntil != nil {
			t.Fatalf("expected suspended user with no lockout expiry, got IsActive=%v lockedUntil=%v", suspended.IsActive, suspended.LockedUntil)
		}

		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != ErrAccountDisabled {
			t.Fatalf("expected ErrAccountDisabled for a suspended account, got %v", err)
		}
	})

	t.Run("suspension does not auto-recover on its own", func(t *testing.T) {
		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != ErrAccountDisabled {
			t.Fatalf("expected suspension to persist across attempts, got %v", err)
		}
	})

	t.Run("reactivate restores login", func(t *testing.T) {
		reactivated, err := auth.UserReactivate(ctx, user.ID)
		if err != nil {
			t.Fatalf("UserReactivate failed: %v", err)
		}
		if !reactivated.IsActive {
			t.Fatal("expected reactivated user to be active")
		}

		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != nil {
			t.Fatalf("expected login to succeed after reactivation, got %v", err)
		}
	})
}

func TestAdminUserAuthHistory(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("adminhistory")
	password := "securepass123"
	user, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password})
	if err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	if _, err := auth.TokenCreate(ctx, user); err != nil {
		t.Fatalf("TokenCreate failed: %v", err)
	}
	if err := auth.PasswordResetRequest(ctx, RequestPasswordReset{Email: email}); err != nil {
		t.Fatalf("PasswordResetRequest failed: %v", err)
	}

	history, err := auth.UserAuthHistory(ctx, user.ID, 0)
	if err != nil {
		t.Fatalf("UserAuthHistory failed: %v", err)
	}
	if len(history) < 2 {
		t.Fatalf("expected at least 2 history entries (refresh + password reset), got %d", len(history))
	}

	types := map[string]bool{}
	for _, entry := range history {
		types[entry.TokenType] = true
	}
	if !types[models.TokenTypeRefresh] || !types[models.TokenTypePasswordReset] {
		t.Fatalf("expected refresh and password_reset token types in history, got %+v", types)
	}
}
