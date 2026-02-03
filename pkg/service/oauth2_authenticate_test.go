package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/util"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

func setupOAuth2AuthTestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("oauth2_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
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

func TestOAuth2Authenticate(t *testing.T) {
	auth := setupOAuth2AuthTestDB(t)
	ctx := context.Background()

	providerID := util.RandomString(16)

	t.Run("NewUser", func(t *testing.T) {
		userInfo := &OAuth2UserInfo{
			ID:    providerID,
			Email: util.UniqueEmail("google"),
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
		updatedEmail := util.UniqueEmail("updated_google")
		userInfo := &OAuth2UserInfo{
			ID:    providerID,
			Email: updatedEmail,
		}
		user, err := auth.OAuth2Authenticate(ctx, "google", userInfo)
		if err != nil {
			t.Fatalf("OAuth2Authenticate failed: %v", err)
		}
		if user.Email != userInfo.Email {
			t.Errorf("expected updated email %s, got %s", userInfo.Email, user.Email)
		}

		// Verify in DB
		fetched, err := auth.Repo.UserGetByProvider(ctx, "google", providerID)
		if err != nil {
			t.Fatalf("failed to fetch user from DB: %v", err)
		}
		if fetched.Email != userInfo.Email {
			t.Errorf("expected updated email in DB %s, got %s", userInfo.Email, fetched.Email)
		}
	})

	t.Run("ExistingUserByEmail", func(t *testing.T) {
		// Create a local user first
		localEmail := util.UniqueEmail("local")
		auth.UserCreate(ctx, &RequestBasicAuth{
			Email:    localEmail,
			Password: "password",
		})

		githubProviderID := util.RandomString(16)
		userInfo := &OAuth2UserInfo{
			ID:    githubProviderID,
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
