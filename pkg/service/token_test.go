package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *Auth {
	// Use a unique DSN for each test run to ensure isolation
	dsn := "file:token_test?mode=memory&cache=shared"

	// Create Auth service with the migrated in-memory DB
	cfg := &config.Config{
		DB: config.Database{
			Dialect: "sqlite3",
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
	}
	auth := New(cfg)

	// Run migrations to set up the schema
	if err := migrations.MigrateUpWithDBConn(auth.Repo.DB(), "sqlite3"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return auth
}

func TestTokenOperations(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	auth.Repo.Ping()
	xlog.Debug("db pinged")

	// Create a dummy user for testing
	user := &models.User{
		Email:        "test@example.com",
		PasswordHash: "some-hash",
		Provider:     "local",
		UserMetadata: models.JSONMap{"name": "Test User"},
	}
	createdUser, err := auth.Repo.UserCreate(ctx, user)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	var refreshToken string

	t.Run("TokenCreate", func(t *testing.T) {
		resp, err := auth.TokenCreate(ctx, createdUser)
		if err != nil {
			t.Fatalf("TokenCreate() unexpected error: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected access token, got empty")
		}
		if resp.RefreshToken == "" {
			t.Error("expected refresh token, got empty")
		}
		if resp.ExpiresIn <= 0 {
			t.Errorf("expected positive expires_in, got %d", resp.ExpiresIn)
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("expected token type Bearer, got %s", resp.TokenType)
		}

		refreshToken = resp.RefreshToken

		// Verify token exists in DB
		storedToken, err := auth.Repo.TokenGetByToken(ctx, refreshToken)
		if err != nil {
			t.Fatalf("failed to get token from db: %v", err)
		}
		if storedToken.UserID != createdUser.ID {
			t.Errorf("expected user id %s, got %s", createdUser.ID, storedToken.UserID)
		}
	})

	t.Run("TokenRefresh", func(t *testing.T) {
		resp, err := auth.TokenRefresh(ctx, refreshToken)
		if err != nil {
			t.Fatalf("TokenRefresh() unexpected error: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected new access token on refresh")
		}
		if resp.RefreshToken != refreshToken {
			t.Errorf("expected same refresh token, got %s", resp.RefreshToken)
		}
	})

	t.Run("TokenRevoke", func(t *testing.T) {
		err := auth.TokenRevoke(ctx, refreshToken)
		if err != nil {
			t.Fatalf("TokenRevoke() unexpected error: %v", err)
		}

		// Verify revocation in DB
		storedToken, err := auth.Repo.TokenGetByToken(ctx, refreshToken)
		if err != nil {
			t.Fatalf("failed to get token from db after revoke: %v", err)
		}
		if !storedToken.Revoked {
			t.Error("expected token to be marked as revoked")
		}

		// Try to refresh with revoked token
		_, err = auth.TokenRefresh(ctx, refreshToken)
		if err == nil {
			t.Error("expected error when refreshing a revoked token, got nil")
		}
		expectedErr := "token revoked"
		if err.Error() != expectedErr {
			t.Errorf("expected error '%s', got '%v'", expectedErr, err)
		}
	})
}
