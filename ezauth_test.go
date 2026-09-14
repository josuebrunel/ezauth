package ezauth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/util"

	_ "github.com/go-sql-driver/mysql"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

func TestEzAuth(t *testing.T) {
	dialect, dsn := util.GetTestDBConfig("ezauth_test")

	t.Cleanup(func() {
		db, err := sql.Open(dialect, dsn)
		if err != nil {
			t.Logf("failed to open db for cleanup: %v", err)
			return
		}
		defer db.Close()

		// Every table any migration has ever created. This list must stay
		// exhaustive: leaving a table out means it survives this reset (and,
		// on postgres/mysql, keeps a shared CI database dirty for the next
		// package's ensureMigrated cycle) while ezauth_goose_db_version and
		// its FK targets (ezauth_users) get dropped -- CREATE TABLE IF NOT
		// EXISTS then silently skips recreating the survivor, so it re-enters
		// the next Up() missing whatever that table's init migration would
		// have (re-)established, e.g. a FK stripped by an upstream CASCADE.
		tables := []string{
			"ezauth_audit_logs",
			"ezauth_org_members",
			"ezauth_organizations",
			"ezauth_role_permissions",
			"ezauth_user_roles",
			"ezauth_permissions",
			"ezauth_roles",
			"ezauth_webauthn_challenges",
			"ezauth_webauthn_credentials",
			"ezauth_tokens",
			"ezauth_users",
			"ezauth_goose_db_version",
		}

		switch dialect {
		case "postgres":
			for _, table := range tables {
				_, _ = db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE")
			}
		case "mysql":
			_, _ = db.Exec("SET FOREIGN_KEY_CHECKS=0")
			for _, table := range tables {
				_, _ = db.Exec("DROP TABLE IF EXISTS " + table)
			}
			_, _ = db.Exec("SET FOREIGN_KEY_CHECKS=1")
		case "sqlite", "sqlite3":
			for _, table := range tables {
				_, _ = db.Exec("DROP TABLE IF EXISTS " + table)
			}
		}
	})

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret-0123456789-0123456789",
	}

	t.Run("New", func(t *testing.T) {
		auth, err := New(cfg, "auth")
		if err != nil {
			t.Fatalf("failed to create ezauth: %v", err)
		}
		if auth == nil {
			t.Fatal("expected ezauth instance, got nil")
		}

		if err := auth.Migrate(); err != nil {
			t.Fatalf("failed to migrate: %v", err)
		}
	})

	t.Run("Wrapper", func(t *testing.T) {
		auth, err := New(cfg, "auth")
		if err != nil {
			t.Fatalf("failed to create ezauth: %v", err)
		}
		if err := auth.Migrate(); err != nil {
			t.Fatalf("failed to migrate: %v", err)
		}

		ctx, err := auth.Handler.Session.Load(context.Background(), "")
		if err != nil {
			t.Fatalf("failed to load session: %v", err)
		}

		if _, err := auth.GetSessionUser(ctx); err == nil {
			t.Error("expected error from GetSessionUser with empty context")
		}

		mw := auth.LoadUserMiddleware(nil)
		if mw == nil {

		}
	})

	t.Run("Impersonation", func(t *testing.T) {
		auth, err := New(cfg, "auth")
		if err != nil {
			t.Fatalf("failed to create ezauth: %v", err)
		}
		if err := auth.Migrate(); err != nil {
			t.Fatalf("failed to migrate: %v", err)
		}

		ctx := context.Background()
		admin, err := auth.Repo.UserCreate(ctx, &models.User{
			Email:        util.UniqueEmail("ezauth-admin"),
			PasswordHash: "some-hash",
			Provider:     "local",
			Roles:        "admin",
		})
		if err != nil {
			t.Fatalf("failed to create admin: %v", err)
		}
		target, err := auth.Repo.UserCreate(ctx, &models.User{
			Email:        util.UniqueEmail("ezauth-target"),
			PasswordHash: "some-hash",
			Provider:     "local",
		})
		if err != nil {
			t.Fatalf("failed to create target: %v", err)
		}

		tokenResp, err := auth.Impersonate(ctx, admin, target.ID)
		if err != nil {
			t.Fatalf("Impersonate() unexpected error: %v", err)
		}
		if tokenResp.AccessToken == "" || tokenResp.RefreshToken == "" {
			t.Fatal("expected access/refresh tokens from Impersonate()")
		}

		sctx, err := auth.Handler.Session.Load(context.Background(), "")
		if err != nil {
			t.Fatalf("failed to load session: %v", err)
		}
		if _, ok := auth.IsImpersonating(sctx); ok {
			t.Error("expected IsImpersonating to be false before setting an impersonation session")
		}
		if _, err := auth.GetImpersonator(sctx); err == nil {
			t.Error("expected GetImpersonator to error before setting an impersonation session")
		}

		if err := auth.StopImpersonating(ctx, admin.ID, tokenResp.RefreshToken); err != nil {
			t.Fatalf("StopImpersonating() unexpected error: %v", err)
		}
	})
}
func TestHelpers(t *testing.T) {
	t.Run("GetUserID", func(t *testing.T) {
		userID := "test-user-id"
		ctx := context.WithValue(context.Background(), ezmiddleware.UserContextKey, userID)

		id, err := GetUserID(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != userID {
			t.Fatalf("expected user ID %s, got %s", userID, id)
		}

		_, err = GetUserID(context.Background())
		if err == nil {
			t.Fatal("expected error when user ID is missing from context")
		}
	})

	t.Run("GetUser", func(t *testing.T) {
		user := &models.User{ID: "test-user-id", Email: "test@example.com"}
		ctx := context.WithValue(context.Background(), ezmiddleware.UserObjectContextKey, user)

		u, err := GetUser(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.ID != user.ID {
			t.Fatalf("expected user ID %s, got %s", user.ID, u.ID)
		}

		_, err = GetUser(context.Background())
		if err == nil {
			t.Fatal("expected error when user object is missing from context")
		}
	})

	t.Run("IsAuthenticated", func(t *testing.T) {

		user := &models.User{ID: "test-user-id"}
		ctx1 := context.WithValue(context.Background(), ezmiddleware.UserObjectContextKey, user)
		if !IsAuthenticated(ctx1) {
			t.Fatal("expected true when user object is in context")
		}

		ctx2 := context.WithValue(context.Background(), ezmiddleware.UserContextKey, "some-id")
		if !IsAuthenticated(ctx2) {
			t.Fatal("expected true when user ID is in context")
		}

		if IsAuthenticated(context.Background()) {
			t.Fatal("expected false when context is empty")
		}
	})

	t.Run("GetImpersonatorID", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ezmiddleware.ImpersonatorContextKey, "admin-id")
		id, err := GetImpersonatorID(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "admin-id" {
			t.Fatalf("expected impersonator id admin-id, got %s", id)
		}

		if _, err := GetImpersonatorID(context.Background()); err == nil {
			t.Fatal("expected error when impersonator id is missing from context")
		}
	})
}
