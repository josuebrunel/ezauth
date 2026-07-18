package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"

	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"

	"github.com/josuebrunel/gopkg/xlog"
)

func setupBasicAuthTestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("basicauth_test")

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

	if err := migrations.MigrateDownWithDBConn(auth.Repo.DB(), dialect); err != nil {

		t.Logf("failed to run migrations down: %v", err)
	}

	if err := migrations.MigrateUpWithDBConn(auth.Repo.DB(), dialect); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return auth
}

func TestBasicAuthOperations(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("basicauth")
	password := "securepass123"
	newPassword := "newsecurepass456"

	var createdUser *models.User

	t.Run("UserCreate", func(t *testing.T) {
		req := &RequestBasicAuth{
			Email:     email,
			Username:  "johndoe",
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
		if user.Username != "johndoe" {
			t.Errorf("expected username johndoe, got %s", user.Username)
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

		// Verify retrieval by Username
		fetchedByUsername, err := auth.Repo.UserGetByUsername(ctx, "johndoe")
		if err != nil {
			t.Fatalf("failed to fetch user by username: %v", err)
		}
		if fetchedByUsername.ID != user.ID {
			t.Errorf("expected retrieved user ID %s, got %s", user.ID, fetchedByUsername.ID)
		}

		createdUser = user
	})

	t.Run("UserCreate_ShortPassword", func(t *testing.T) {
		req := &RequestBasicAuth{
			Email:    util.UniqueEmail("short"),
			Password: "short",
		}
		_, err := auth.UserCreate(ctx, req)
		if err == nil {
			t.Fatal("expected error for short password, got nil")
		}
		if err.Error() != "password must be at least 8 characters long" {
			t.Errorf("expected 'password must be at least 8 characters long', got '%v'", err)
		}
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

		_, err = auth.UserAuthenticate(ctx, RequestBasicAuth{
			Email:    email,
			Password: password,
		})
		if err == nil {
			t.Error("expected authentication failure with old password")
		}

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

		createdUser = updatedUser
	})
}
func TestPasswordless(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("magic")

	err := auth.PasswordlessRequest(ctx, RequestPasswordless{Email: email})
	if err != nil {
		t.Fatalf("PasswordlessRequest() failed: %v", err)
	}

	mockMailer := auth.Mailer.(*MockMailer)
	if len(mockMailer.SentEmails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mockMailer.SentEmails))
	}

	sentBody := mockMailer.SentEmails[0]["body"]

	tokenValue := sentBody[len(sentBody)-64:]

	expectedPath := "/auth/passwordless/login"
	if !strings.Contains(sentBody, expectedPath) {
		t.Errorf("expected email body to contain path '%s', got '%s'", expectedPath, sentBody)
	}

	resp, err := auth.PasswordlessLogin(ctx, tokenValue)
	if err != nil {
		t.Fatalf("PasswordlessLogin() failed: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected access token")
	}

	user, err := auth.Repo.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if user.Email != email {
		t.Errorf("expected email %s, got %s", email, user.Email)
	}
	if !user.EmailVerified {
		t.Error("expected email to be verified")
	}

	token, err := auth.Repo.TokenGetByToken(ctx, tokenValue)
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}

	if !token.Revoked {
		t.Error("expected token to be revoked after use")
	}
}
func TestOAuth2GetConfig(t *testing.T) {
	cfg := &config.Config{
		OAuth2: config.OAuth2{
			Google: config.OAuth2Google{
				ClientID:     "g-id",
				ClientSecret: "g-secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       "email,profile",
			},
		},
	}
	auth := &Auth{Cfg: cfg}

	t.Run("Google", func(t *testing.T) {
		conf, err := auth.OAuth2GetConfig("google")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.ClientID != "g-id" {
			t.Errorf("expected client id 'g-id', got '%s'", conf.ClientID)
		}
		if len(conf.Scopes) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(conf.Scopes))
		}
	})

	t.Run("Unsupported", func(t *testing.T) {
		_, err := auth.OAuth2GetConfig("unknown")
		if err == nil {
			t.Fatal("expected error for unknown provider")
		}
	})
}
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

		fetched, err := auth.Repo.UserGetByProvider(ctx, "google", providerID)
		if err != nil {
			t.Fatalf("failed to fetch user from DB: %v", err)
		}
		if fetched.Email != userInfo.Email {
			t.Errorf("expected updated email in DB %s, got %s", userInfo.Email, fetched.Email)
		}
	})

	t.Run("ExistingUserByEmail", func(t *testing.T) {

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
func TestPasswordReset(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("reset")
	password := "old-password"
	user := &models.User{
		Email:    email,
		Provider: "local",
	}
	user.PasswordHash, _ = auth.UserHashPassword(password)
	createdUser, err := auth.Repo.UserCreate(ctx, user)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	err = auth.PasswordResetRequest(ctx, RequestPasswordReset{Email: email})
	if err != nil {
		t.Fatalf("PasswordResetRequest() failed: %v", err)
	}

	mockMailer := auth.Mailer.(*MockMailer)
	if len(mockMailer.SentEmails) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mockMailer.SentEmails))
	}

	sentBody := mockMailer.SentEmails[0]["body"]
	tokenStart := strings.Index(sentBody, "token=")
	if tokenStart == -1 {
		t.Fatalf("could not find token in email body: %s", sentBody)
	}
	tokenValue := sentBody[tokenStart+6:]

	newPassword := "new-password"
	err = auth.PasswordResetConfirm(ctx, RequestPasswordResetConfirm{
		Token:    tokenValue,
		Password: newPassword,
	})
	if err != nil {
		t.Fatalf("PasswordResetConfirm() failed: %v", err)
	}

	authenticatedUser, err := auth.UserAuthenticate(ctx, RequestBasicAuth{
		Email:    email,
		Password: newPassword,
	})
	if err != nil {
		t.Fatalf("UserAuthenticate() failed after reset: %v", err)
	}
	if authenticatedUser.ID != createdUser.ID {
		t.Errorf("expected user id %s, got %s", createdUser.ID, authenticatedUser.ID)
	}

	storedToken, err := auth.Repo.TokenGetByToken(ctx, tokenValue)
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}
	if !storedToken.Revoked {
		t.Error("expected token to be revoked after use")
	}

	err = auth.PasswordResetConfirm(ctx, RequestPasswordResetConfirm{
		Token:    tokenValue,
		Password: "another-password",
	})
	if err == nil {
		t.Error("expected error when using revoked token, got nil")
	}
}
func setupTestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("token_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		EmailTemplates: config.EmailTemplates{
			PasswordlessSubject:  "Magic Link Login",
			PasswordlessBody:     "Click the following link to login: {{.Link}}",
			PasswordResetSubject: "Password Reset Request",
			PasswordResetBody:    "Click the following link to reset your password: {{.Link}}",
		},
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

func TestTokenOperations(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	auth.Repo.Ping()
	xlog.Debug("db pinged")

	user := &models.User{
		Email:        util.UniqueEmail("token"),
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

		storedToken, err := auth.Repo.TokenGetByToken(ctx, refreshToken)
		if err != nil {
			t.Fatalf("failed to get token from db: %v", err)
		}
		if storedToken.UserID != createdUser.ID {
			t.Errorf("expected user id %s, got %s", createdUser.ID, storedToken.UserID)
		}
	})

	t.Run("TokenRefresh", func(t *testing.T) {
		oldRefreshToken := refreshToken
		resp, err := auth.TokenRefresh(ctx, oldRefreshToken)
		if err != nil {
			t.Fatalf("TokenRefresh() unexpected error: %v", err)
		}

		if resp.AccessToken == "" {
			t.Error("expected new access token on refresh")
		}
		if resp.RefreshToken == oldRefreshToken {
			t.Error("expected new refresh token (rotation), got the same one")
		}

		storedOldToken, err := auth.Repo.TokenGetByToken(ctx, oldRefreshToken)
		if err != nil {
			t.Fatalf("failed to get old token: %v", err)
		}
		if !storedOldToken.Revoked {
			t.Error("expected old refresh token to be revoked after refresh")
		}

		refreshToken = resp.RefreshToken
	})

	t.Run("TokenRevoke", func(t *testing.T) {
		err := auth.TokenRevoke(ctx, refreshToken)
		if err != nil {
			t.Fatalf("TokenRevoke() unexpected error: %v", err)
		}

		storedToken, err := auth.Repo.TokenGetByToken(ctx, refreshToken)
		if err != nil {
			t.Fatalf("failed to get token from db after revoke: %v", err)
		}
		if !storedToken.Revoked {
			t.Error("expected token to be marked as revoked")
		}

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
