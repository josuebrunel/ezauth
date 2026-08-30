package service

import (
	"context"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func setupLockoutTestDB(t *testing.T, maxAttempts int, lockoutDuration time.Duration) *Auth {
	dialect, dsn := util.GetTestDBConfig("lockout_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		AccountLockout: config.AccountLockout{
			Enabled:         true,
			MaxAttempts:     maxAttempts,
			LockoutDuration: lockoutDuration,
		},
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := migrations.MigrateUpWithDBConn(auth.Repo.DB(), dialect); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func TestAccountLockout(t *testing.T) {
	auth := setupLockoutTestDB(t, 3, time.Hour)
	ctx := context.Background()

	email := util.UniqueEmail("lockout")
	password := "correct-horse-battery"
	if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	wrongLogin := func() error {
		_, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong-password"})
		return err
	}

	t.Run("failed attempts below threshold stay unlocked", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			if err := wrongLogin(); err == nil {
				t.Fatal("expected error for wrong password")
			}
		}
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if !user.IsActive || user.FailedLoginAttempts != 2 {
			t.Fatalf("expected active user with 2 failed attempts, got IsActive=%v attempts=%d", user.IsActive, user.FailedLoginAttempts)
		}
	})

	t.Run("threshold locks the account", func(t *testing.T) {
		if err := wrongLogin(); err == nil {
			t.Fatal("expected error for wrong password")
		}

		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.IsActive || user.LockedUntil == nil {
			t.Fatalf("expected locked user, got IsActive=%v lockedUntil=%v", user.IsActive, user.LockedUntil)
		}

		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != ErrAccountLocked {
			t.Fatalf("expected ErrAccountLocked even with correct password, got %v", err)
		}
	})

	t.Run("account auto-unlocks once the window passes", func(t *testing.T) {
		// Force the lockout into the past to simulate the window elapsing.
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		past := time.Now().Add(-time.Minute)
		if _, err := auth.Repo.UserSetLockoutState(ctx, user.ID, user.FailedLoginAttempts, &past, false); err != nil {
			t.Fatalf("failed to force lockout into the past: %v", err)
		}

		authenticated, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password})
		if err != nil {
			t.Fatalf("expected auto-unlock to allow login, got %v", err)
		}
		if !authenticated.IsActive || authenticated.FailedLoginAttempts != 0 {
			t.Fatalf("expected reset lockout state, got IsActive=%v attempts=%d", authenticated.IsActive, authenticated.FailedLoginAttempts)
		}
	})

	t.Run("a successful login resets the failed attempt counter", func(t *testing.T) {
		if err := wrongLogin(); err == nil {
			t.Fatal("expected error for wrong password")
		}
		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != nil {
			t.Fatalf("UserAuthenticate with correct password failed: %v", err)
		}
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.FailedLoginAttempts != 0 {
			t.Fatalf("expected failed attempt counter reset to 0, got %d", user.FailedLoginAttempts)
		}
	})
}

func TestAccountLockoutDisabledByDefault(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("nolockout")
	password := "correct-horse-battery"
	if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong"}); err == nil {
			t.Fatal("expected error for wrong password")
		}
	}

	if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("expected login to still succeed with lockout disabled, got %v", err)
	}
}
