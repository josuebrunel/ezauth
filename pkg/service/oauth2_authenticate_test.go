package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	_ "github.com/mattn/go-sqlite3"
)

func setupOAuth2AuthTestDB(t *testing.T) *Auth {
	dsn := "file:oauth2auth_test?mode=memory&cache=shared"
	cfg := &config.Config{
		DB: config.Database{
			Dialect: "sqlite3",
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
	}
	auth, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := migrations.MigrateUpWithDBConn(auth.Repo.DB(), "sqlite"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func TestOAuth2Authenticate(t *testing.T) {
	auth := setupOAuth2AuthTestDB(t)
	ctx := context.Background()

	t.Run("NewUser", func(t *testing.T) {
		userInfo := &OAuth2UserInfo{
			ID:    "google-123",
			Email: "google-user@example.com",
		}
		user, err := auth.OAuth2Authenticate(ctx, "google", userInfo)
		if err != nil {
			t.Fatalf("OAuth2Authenticate failed: %v", err)
		}
		if user.Email != userInfo.Email {
			t.Errorf("expected email %s, got %s", userInfo.Email, user.Email)
		}
		if user.Provider != "google" {
			t.Errorf("expected provider google, got %s", user.Provider)
		}
		if *user.ProviderID != userInfo.ID {
			t.Errorf("expected provider id %s, got %s", userInfo.ID, *user.ProviderID)
		}
		if !user.EmailVerified {
			t.Error("expected email to be verified")
		}
	})

	t.Run("ExistingUserByProvider", func(t *testing.T) {
		userInfo := &OAuth2UserInfo{
			ID:    "google-123",
			Email: "updated-google-user@example.com",
		}
		user, err := auth.OAuth2Authenticate(ctx, "google", userInfo)
		if err != nil {
			t.Fatalf("OAuth2Authenticate failed: %v", err)
		}
		if user.Email != userInfo.Email {
			t.Errorf("expected updated email %s, got %s", userInfo.Email, user.Email)
		}

		// Verify in DB
		fetched, err := auth.Repo.UserGetByProvider(ctx, "google", "google-123")
		if err != nil {
			t.Fatalf("failed to fetch user from DB: %v", err)
		}
		if fetched.Email != userInfo.Email {
			t.Errorf("expected updated email in DB %s, got %s", userInfo.Email, fetched.Email)
		}
	})

	t.Run("ExistingUserByEmail", func(t *testing.T) {
		// Create a local user first
		localEmail := "local-user@example.com"
		auth.UserCreate(ctx, &RequestBasicAuth{
			Email:    localEmail,
			Password: "password",
		})

		userInfo := &OAuth2UserInfo{
			ID:    "github-456",
			Email: localEmail,
		}
		user, err := auth.OAuth2Authenticate(ctx, "github", userInfo)
		if err != nil {
			t.Fatalf("OAuth2Authenticate failed: %v", err)
		}

		if user.Email != localEmail {
			t.Errorf("expected email %s, got %s", localEmail, user.Email)
		}
		if user.Provider != "github" {
			t.Errorf("expected provider github, got %s", user.Provider)
		}
		if *user.ProviderID != userInfo.ID {
			t.Errorf("expected provider id %s, got %s", userInfo.ID, *user.ProviderID)
		}
	})
}
