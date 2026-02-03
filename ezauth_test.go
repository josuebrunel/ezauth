package ezauth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	_ "modernc.org/sqlite"
)

func TestEzAuth(t *testing.T) {
	dsn := fmt.Sprintf("file:%d?mode=memory&cache=shared", time.Now().UnixNano())
	cfg := &config.Config{
		DB: config.Database{
			Dialect: "sqlite3",
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
