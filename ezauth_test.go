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

		switch dialect {
		case "postgres":
			_, _ = db.Exec("DROP TABLE IF EXISTS ezauth_tokens CASCADE")
			_, _ = db.Exec("DROP TABLE IF EXISTS ezauth_users CASCADE")
		case "mysql":
			_, _ = db.Exec("SET FOREIGN_KEY_CHECKS=0")
			_, _ = db.Exec("DROP TABLE IF EXISTS ezauth_tokens")
			_, _ = db.Exec("DROP TABLE IF EXISTS ezauth_users")
			_, _ = db.Exec("SET FOREIGN_KEY_CHECKS=1")
		case "sqlite", "sqlite3":
			_, _ = db.Exec("DROP TABLE IF EXISTS ezauth_tokens")
			_, _ = db.Exec("DROP TABLE IF EXISTS ezauth_users")
		}
	})

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
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
}
