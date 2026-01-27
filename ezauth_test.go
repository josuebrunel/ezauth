package ezauth

import (
	"fmt"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	_ "github.com/mattn/go-sqlite3"
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
}
