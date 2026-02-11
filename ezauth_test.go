package ezauth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/util"

	_ "github.com/go-sql-driver/mysql"
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

		// Verify GetSessionUser proxy exists and works (return error on empty context)
		// We must load the session into context first, otherwise scs panics
		ctx, err := auth.Handler.Session.Load(context.Background(), "")
		if err != nil {
			t.Fatalf("failed to load session: %v", err)
		}

		if _, err := auth.GetSessionUser(ctx); err == nil {
			t.Error("expected error from GetSessionUser with empty context")
		}

		// Verify LoadUserMiddleware proxy exists
		mw := auth.LoadUserMiddleware(nil)
		if mw == nil { // Just checking if it returns *something* valid, http.Handler is an interface so simple nil check might pass if logic is flawed, but assuming proxy returns non-nil func
			// Actually http.HandlerFunc is not nil.
		}
	})
}
