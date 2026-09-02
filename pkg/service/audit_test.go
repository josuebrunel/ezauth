package service

import (
	"context"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

// setupAuditTestDB is setupTestDB (see auth_test.go) plus AuditLog.Enabled,
// which — like AccountLockout.Enabled — only defaults to true via env-based
// config loading (xenv's `default:"true"` tag), not on a bare Go struct
// literal, so tests that need it must opt in explicitly (see setupLockoutTestDB).
func setupAuditTestDB(t *testing.T, maxAttempts int, lockoutDuration time.Duration) *Auth {
	dialect, dsn := util.GetTestDBConfig("audit_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
		AuditLog:  config.AuditLog{Enabled: true},
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
	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func auditTestUser(t *testing.T, auth *Auth, ctx context.Context) *models.User {
	t.Helper()
	req := RequestBasicAuth{
		Email:    util.UniqueEmail("audit"),
		Password: "correct-horse-battery-staple",
	}
	user, err := auth.UserCreate(ctx, &req)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	return user
}

func TestAuditLog(t *testing.T) {
	ctx := context.Background()

	t.Run("Hook.AfterUserCreated records a user.created event", func(t *testing.T) {
		auth := setupAuditTestDB(t, 5, time.Hour)
		user := auditTestUser(t, auth, ctx)

		// Mirrors what handlers actually do: call the user-created hook
		// themselves after Auth.UserCreate returns (see e.g. FormRegister).
		if err := auth.Hook.AfterUserCreated(ctx, user); err != nil {
			t.Fatalf("AfterUserCreated failed: %v", err)
		}

		result, err := auth.AuditLogs(ctx, user.ID, ListAuditLogsOptions{})
		if err != nil {
			t.Fatalf("AuditLogs failed: %v", err)
		}
		if len(result.Events) != 1 || result.Events[0].EventType != models.AuditEventUserCreated {
			t.Fatalf("expected 1 user.created event, got %+v", result.Events)
		}
	})

	t.Run("failed login records a login.failed event", func(t *testing.T) {
		auth := setupAuditTestDB(t, 5, time.Hour)
		user := auditTestUser(t, auth, ctx)

		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: user.Email, Password: "wrong-password"}); err == nil {
			t.Fatal("expected authentication to fail")
		}

		result, err := auth.AuditLogs(ctx, user.ID, ListAuditLogsOptions{EventType: models.AuditEventLoginFailed})
		if err != nil {
			t.Fatalf("AuditLogs failed: %v", err)
		}
		if len(result.Events) != 1 {
			t.Fatalf("expected 1 login.failed event, got %d", len(result.Events))
		}
		if reason, _ := result.Events[0].Metadata["reason"].(string); reason != "invalid_password" {
			t.Errorf("expected reason=invalid_password, got %v", result.Events[0].Metadata)
		}
	})

	t.Run("account lockout records an account.locked event", func(t *testing.T) {
		auth := setupAuditTestDB(t, 2, time.Hour)
		user := auditTestUser(t, auth, ctx)

		for range 2 {
			if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: user.Email, Password: "wrong-password"}); err == nil {
				t.Fatal("expected authentication to fail")
			}
		}

		result, err := auth.AuditLogs(ctx, user.ID, ListAuditLogsOptions{EventType: models.AuditEventAccountLocked})
		if err != nil {
			t.Fatalf("AuditLogs failed: %v", err)
		}
		if len(result.Events) != 1 {
			t.Fatalf("expected 1 account.locked event, got %d", len(result.Events))
		}
	})

	t.Run("disabling audit logging records nothing", func(t *testing.T) {
		auth := setupAuditTestDB(t, 5, time.Hour)
		auth.Cfg.AuditLog.Enabled = false
		user := auditTestUser(t, auth, ctx)

		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: user.Email, Password: "wrong-password"}); err == nil {
			t.Fatal("expected authentication to fail")
		}

		result, err := auth.AuditLogs(ctx, user.ID, ListAuditLogsOptions{})
		if err != nil {
			t.Fatalf("AuditLogs failed: %v", err)
		}
		if len(result.Events) != 0 {
			t.Fatalf("expected 0 events with audit logging disabled, got %d", len(result.Events))
		}
	})

	t.Run("a custom Hook is still called alongside audit persistence", func(t *testing.T) {
		auth := setupAuditTestDB(t, 5, time.Hour)
		called := false
		auth.SetHook(&stubHook{onAfterUserCreated: func() { called = true }})

		user := auditTestUser(t, auth, ctx)
		if err := auth.Hook.AfterUserCreated(ctx, user); err != nil {
			t.Fatalf("AfterUserCreated failed: %v", err)
		}

		if !called {
			t.Error("expected custom hook to be called")
		}
		result, err := auth.AuditLogs(ctx, user.ID, ListAuditLogsOptions{})
		if err != nil {
			t.Fatalf("AuditLogs failed: %v", err)
		}
		if len(result.Events) != 1 {
			t.Fatalf("expected audit logging to still run alongside the custom hook, got %d events", len(result.Events))
		}
	})
}

// stubHook is a minimal Hook implementation for testing that auditHook
// still delegates to a consumer-registered hook.
type stubHook struct {
	DefaultHook
	onAfterUserCreated func()
}

func (h *stubHook) AfterUserCreated(ctx context.Context, user *models.User) error {
	if h.onAfterUserCreated != nil {
		h.onAfterUserCreated()
	}
	return nil
}
