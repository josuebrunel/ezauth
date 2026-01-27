package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	_ "github.com/mattn/go-sqlite3"
)

func setupBasicAuthTestDB(t *testing.T) *Auth {
	// Use a unique DSN for each test run to ensure isolation
	dsn := "file:basicauth_test?mode=memory&cache=shared"

	// Create Auth service with the migrated in-memory DB
	cfg := &config.Config{
		DB: config.Database{
			Dialect: "sqlite3",
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	// Run migrations to set up the schema
	if err := migrations.MigrateUpWithDBConn(auth.Repo.DB(), "sqlite"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return auth
}

func TestBasicAuthOperations(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	email := "test@basicauth.com"
	password := "securepass123"
	newPassword := "newsecurepass456"

	var createdUser *models.User

	t.Run("UserCreate", func(t *testing.T) {
		req := &RequestBasicAuth{
			Email:     email,
			Password:  password,
			FirstName: "John",
			LastName:  "Doe",
			Locale:    "en-US",
			Timezone:  "UTC",
			Roles:     "admin,user",
			Data:      map[string]any{"role": "admin"},
		}

		user, err := auth.UserCreate(ctx, req)
		if err != nil {
			t.Fatalf("UserCreate failed: %v", err)
		}
		if user.Email != email {
			t.Errorf("expected email %s, got %s", email, user.Email)
		}
		if user.ID == "" {
			t.Error("expected user ID to be set")
		}
		if user.FirstName != "John" {
			t.Errorf("expected FirstName John, got %s", user.FirstName)
		}
		if user.LastName != "Doe" {
			t.Errorf("expected LastName Doe, got %s", user.LastName)
		}
		if user.Locale != "en-US" {
			t.Errorf("expected Locale en-US, got %s", user.Locale)
		}
		if user.Timezone != "UTC" {
			t.Errorf("expected Timezone UTC, got %s", user.Timezone)
		}
		if user.Roles != "admin,user" {
			t.Errorf("expected Roles admin,user, got %s", user.Roles)
		}
		createdUser = user
	})

	t.Run("UserAuthenticate_Success", func(t *testing.T) {
		req := RequestBasicAuth{
			Email:    email,
			Password: password,
		}
		user, err := auth.UserAuthenticate(ctx, req)
		if err != nil {
			t.Fatalf("UserAuthenticate failed: %v", err)
		}
		if user.ID != createdUser.ID {
			t.Errorf("expected user ID %s, got %s", createdUser.ID, user.ID)
		}
	})

	t.Run("UserAuthenticate_InvalidPassword", func(t *testing.T) {
		req := RequestBasicAuth{
			Email:    email,
			Password: "wrongpassword",
		}
		_, err := auth.UserAuthenticate(ctx, req)
		if err == nil {
			t.Error("expected error for invalid password, got nil")
		}
		if err.Error() != "invalid credentials" {
			t.Errorf("expected 'invalid credentials', got '%v'", err)
		}
	})

	t.Run("UserUpdatePassword", func(t *testing.T) {
		updatedUser, err := auth.UserUpdatePassword(ctx, createdUser, newPassword)
		if err != nil {
			t.Fatalf("UserUpdatePassword failed: %v", err)
		}

		// Verify old password fails
		_, err = auth.UserAuthenticate(ctx, RequestBasicAuth{
			Email:    email,
			Password: password,
		})
		if err == nil {
			t.Error("expected authentication failure with old password")
		}

		// Verify new password works
		_, err = auth.UserAuthenticate(ctx, RequestBasicAuth{
			Email:    email,
			Password: newPassword,
		})
		if err != nil {
			t.Errorf("authentication failed with new password: %v", err)
		}
		createdUser = updatedUser
	})

	t.Run("UserUpdate", func(t *testing.T) {
		createdUser.UserMetadata = map[string]any{"role": "superadmin"}
		createdUser.FirstName = "Jane"
		createdUser.LastName = "Smith"
		createdUser.Locale = "fr-FR"
		createdUser.Timezone = "Europe/Paris"
		createdUser.Roles = "superadmin"

		updatedUser, err := auth.UserUpdate(ctx, createdUser)
		if err != nil {
			t.Fatalf("UserUpdate failed: %v", err)
		}

		// Verify update in DB by fetching fresh
		fetchedUser, err := auth.Repo.UserGetByID(ctx, createdUser.ID)
		if err != nil {
			t.Fatalf("failed to fetch user: %v", err)
		}

		role := fetchedUser.UserMetadata["role"]
		if role != "superadmin" {
			t.Errorf("expected role 'superadmin', got %v", role)
		}
		if fetchedUser.FirstName != "Jane" {
			t.Errorf("expected FirstName Jane, got %s", fetchedUser.FirstName)
		}
		if fetchedUser.LastName != "Smith" {
			t.Errorf("expected LastName Smith, got %s", fetchedUser.LastName)
		}
		if fetchedUser.Locale != "fr-FR" {
			t.Errorf("expected Locale fr-FR, got %s", fetchedUser.Locale)
		}
		if fetchedUser.Timezone != "Europe/Paris" {
			t.Errorf("expected Timezone Europe/Paris, got %s", fetchedUser.Timezone)
		}
		if fetchedUser.Roles != "superadmin" {
			t.Errorf("expected Roles superadmin, got %s", fetchedUser.Roles)
		}
		// Update reference
		createdUser = updatedUser
	})
}
