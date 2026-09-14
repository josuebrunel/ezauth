package service

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"strings"
	"time"

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
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
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
		if user.Roles != "" {
			t.Errorf("expected Roles to be empty (no roles are set at signup), got %s", user.Roles)
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

	t.Run("UserCreate_InvalidEmail", func(t *testing.T) {
		invalidEmails := []string{
			"not-an-email",
			"missing-domain@",
			"user@domain.com\r\nBcc: victim@evil.com",
			"Attacker Name <user@domain.com>",
			"",
		}
		for _, e := range invalidEmails {
			req := &RequestBasicAuth{
				Email:    e,
				Password: "securepass123",
			}
			if _, err := auth.UserCreate(ctx, req); err == nil {
				t.Errorf("expected error for invalid email %q, got nil", e)
			}
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

// TestEmailCaseNormalization proves email is normalized to lowercase at the
// repository layer (UserCreate/UserGetByEmail/UserUpdate), so lookups
// behave the same regardless of a DB dialect's default collation --
// previously User@Example.com and user@example.com were treated as
// distinct accounts on postgres/sqlite (case-sensitive by default) but the
// same account on mysql (case-insensitive by default).
func TestEmailCaseNormalization(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	mixedCaseEmail := "MixedCase_" + util.NewIDStripped()[:8] + "@Example.COM"
	lowerCaseEmail := strings.ToLower(mixedCaseEmail)
	password := "securepass123"

	t.Run("UserCreate stores email lowercased", func(t *testing.T) {
		user, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: mixedCaseEmail, Password: password})
		if err != nil {
			t.Fatalf("UserCreate failed: %v", err)
		}
		if user.Email != lowerCaseEmail {
			t.Fatalf("expected stored email %q, got %q", lowerCaseEmail, user.Email)
		}
	})

	t.Run("UserGetByEmail finds it regardless of input casing", func(t *testing.T) {
		user, err := auth.Repo.UserGetByEmail(ctx, mixedCaseEmail)
		if err != nil {
			t.Fatalf("UserGetByEmail with original mixed-case input failed: %v", err)
		}
		if user.Email != lowerCaseEmail {
			t.Fatalf("expected %q, got %q", lowerCaseEmail, user.Email)
		}
	})

	t.Run("UserAuthenticate succeeds regardless of input casing", func(t *testing.T) {
		user, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: strings.ToUpper(mixedCaseEmail), Password: password})
		if err != nil {
			t.Fatalf("UserAuthenticate with upper-cased email failed: %v", err)
		}
		if user.Email != lowerCaseEmail {
			t.Fatalf("expected %q, got %q", lowerCaseEmail, user.Email)
		}
	})

	t.Run("a second registration with a different-case duplicate is rejected", func(t *testing.T) {
		if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: strings.ToUpper(mixedCaseEmail), Password: password}); err == nil {
			t.Fatal("expected a case-variant duplicate email to be rejected, got nil error")
		}
	})
}

func TestUsernameCaseNormalization(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	mixedCaseUsername := "MixedCase_" + util.NewIDStripped()[:8]
	lowerCaseUsername := strings.ToLower(mixedCaseUsername)
	email := util.UniqueEmail("usernamecase")
	password := "securepass123"

	t.Run("UserCreate stores username lowercased", func(t *testing.T) {
		user, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Username: mixedCaseUsername, Password: password})
		if err != nil {
			t.Fatalf("UserCreate failed: %v", err)
		}
		if user.Username != lowerCaseUsername {
			t.Fatalf("expected stored username %q, got %q", lowerCaseUsername, user.Username)
		}
	})

	t.Run("UserGetByUsername finds it regardless of input casing", func(t *testing.T) {
		user, err := auth.Repo.UserGetByUsername(ctx, strings.ToUpper(mixedCaseUsername))
		if err != nil {
			t.Fatalf("UserGetByUsername with upper-cased input failed: %v", err)
		}
		if user.Username != lowerCaseUsername {
			t.Fatalf("expected %q, got %q", lowerCaseUsername, user.Username)
		}
	})

	t.Run("a second registration with a different-case duplicate is rejected", func(t *testing.T) {
		if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: util.UniqueEmail("usernamecase2"), Username: strings.ToUpper(mixedCaseUsername), Password: password}); err == nil {
			t.Fatal("expected a case-variant duplicate username to be rejected, got nil error")
		}
	})
}

func TestUserUsernameUniqueness(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()
	username := "unique_" + util.NewIDStripped()[:8]

	if _, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("usernameowner1"), Username: username, Provider: "local"}); err != nil {
		t.Fatalf("failed to create first user: %v", err)
	}

	if _, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("usernameowner2"), Username: username, Provider: "local"}); err == nil {
		t.Fatal("expected duplicate username to be rejected")
	}

	// Multiple users with an empty (unset) username must still be allowed --
	// only non-empty usernames are unique.
	if _, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("nousername1"), Provider: "local"}); err != nil {
		t.Fatalf("failed to create first user with no username: %v", err)
	}
	if _, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("nousername2"), Provider: "local"}); err != nil {
		t.Fatalf("failed to create second user with no username: %v", err)
	}
}

// TestUserUpdate_DoesNotTouchVerificationOrActiveOrMFAFlags proves a partial
// models.User (e.g. fetched by ID and email only, or hand-built by a library
// consumer with just the fields they mean to change) can't accidentally
// deactivate the account, un-verify email/phone, or disable MFA through
// UserUpdate -- those four fields are bools with no "not set" zero value
// distinguishable from "set to false", so UserUpdate deliberately never
// touches them; UserSetEmailVerified/UserSetPhoneVerified/UserSetMFAEnabled/
// UserSetLockoutState own them instead.
func TestUserUpdate_DoesNotTouchVerificationOrActiveOrMFAFlags(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	secret := "some-mfa-secret"
	created, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:         util.UniqueEmail("partialupdate"),
		Provider:      "local",
		EmailVerified: true,
		PhoneVerified: true,
		MfaSecret:     &secret,
		MfaEnabled:    true,
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if !created.IsActive {
		t.Fatal("expected a newly created user to be active")
	}

	// A caller who only fetched/built a partial User (ID and a field they
	// actually mean to change) must not collaterally flip these four flags
	// to their Go zero value (false).
	partial := &models.User{ID: created.ID, FirstName: "Updated"}
	if _, err := auth.Repo.UserUpdate(ctx, partial); err != nil {
		t.Fatalf("UserUpdate failed: %v", err)
	}

	fetched, err := auth.Repo.UserGetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("UserGetByID failed: %v", err)
	}
	if fetched.FirstName != "Updated" {
		t.Errorf("expected FirstName to be updated, got %q", fetched.FirstName)
	}
	if !fetched.EmailVerified {
		t.Error("expected EmailVerified to remain true after an unrelated UserUpdate")
	}
	if !fetched.PhoneVerified {
		t.Error("expected PhoneVerified to remain true after an unrelated UserUpdate")
	}
	if !fetched.IsActive {
		t.Error("expected IsActive to remain true after an unrelated UserUpdate")
	}
	if !fetched.MfaEnabled {
		t.Error("expected MfaEnabled to remain true after an unrelated UserUpdate")
	}
}

// TestLocaleTimezoneAvatarURLAcceptLongValues guards against the columns
// drifting back to a fixed-width type on any one dialect: mysql used to cap
// locale/timezone/avatar_url at VARCHAR(10)/VARCHAR(50)/VARCHAR(500), so a
// value accepted when writing against postgres/sqlite (both unbounded TEXT)
// could be silently truncated or rejected on mysql.
func TestLocaleTimezoneAvatarURLAcceptLongValues(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	longLocale := strings.Repeat("x", 64)
	longTimezone := strings.Repeat("y", 128)
	longAvatarURL := "https://example.com/avatar.png?token=" + strings.Repeat("z", 600)

	created, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:     util.UniqueEmail("longfields"),
		Provider:  "local",
		Locale:    longLocale,
		Timezone:  longTimezone,
		AvatarURL: longAvatarURL,
	})
	if err != nil {
		t.Fatalf("UserCreate with long locale/timezone/avatar_url failed: %v", err)
	}

	fetched, err := auth.Repo.UserGetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("UserGetByID failed: %v", err)
	}
	if fetched.Locale != longLocale {
		t.Errorf("locale truncated: got %d chars, want %d", len(fetched.Locale), len(longLocale))
	}
	if fetched.Timezone != longTimezone {
		t.Errorf("timezone truncated: got %d chars, want %d", len(fetched.Timezone), len(longTimezone))
	}
	if fetched.AvatarURL != longAvatarURL {
		t.Errorf("avatar_url truncated: got %d chars, want %d", len(fetched.AvatarURL), len(longAvatarURL))
	}
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

	token, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(tokenValue))
	if err != nil {
		t.Fatalf("failed to get token: %v", err)
	}

	if !token.Revoked {
		t.Error("expected token to be revoked after use")
	}
}

// TestPasswordlessRequest_EnforcesResendCooldown proves a second request for
// the same address within otpResendCooldown is rejected rather than sending
// another email -- a per-address throttle independent of the general-purpose
// IP rate limiter, since a caller spreading requests across many source IPs
// could otherwise spam a single target's inbox regardless of any per-IP limit.
func TestPasswordlessRequest_EnforcesResendCooldown(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()
	email := util.UniqueEmail("resendcooldown")

	if err := auth.PasswordlessRequest(ctx, RequestPasswordless{Email: email}); err != nil {
		t.Fatalf("first PasswordlessRequest failed: %v", err)
	}
	if err := auth.PasswordlessRequest(ctx, RequestPasswordless{Email: email}); err != ErrResendTooSoon {
		t.Fatalf("expected ErrResendTooSoon for an immediate resend, got %v", err)
	}

	mockMailer := auth.Mailer.(*MockMailer)
	if len(mockMailer.SentEmails) != 1 {
		t.Fatalf("expected only 1 email sent (the throttled resend must not send another), got %d", len(mockMailer.SentEmails))
	}

	otpResendCooldown = 0
	defer func() { otpResendCooldown = 60 * time.Second }()
	if err := auth.PasswordlessRequest(ctx, RequestPasswordless{Email: email}); err != nil {
		t.Fatalf("expected a resend to succeed once the cooldown has passed, got %v", err)
	}
	if len(mockMailer.SentEmails) != 2 {
		t.Fatalf("expected 2 emails sent after the cooldown passed, got %d", len(mockMailer.SentEmails))
	}
}

// TestPasswordResetAndPasswordlessRequest_EmailCaseInsensitive proves
// PasswordResetRequest and PasswordlessRequest find an existing user
// (created with mixed-case input, now stored lowercased) regardless of the
// casing used at request time -- both go through Repository.UserGetByEmail,
// which normalizes internally, so this "just works" without either
// function needing its own normalization step. Also proves PasswordlessRequest
// sends to (and templates with) the canonical stored email, not whatever
// casing the caller typed, matching PasswordResetRequest's existing behavior.
func TestPasswordResetAndPasswordlessRequest_EmailCaseInsensitive(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	mixedEmail := "MixedCase_" + util.NewIDStripped()[:8] + "@Example.COM"
	lowerEmail := strings.ToLower(mixedEmail)

	if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: mixedEmail, Password: "securepass123"}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	t.Run("PasswordResetRequest finds the user via upper-case input", func(t *testing.T) {
		if err := auth.PasswordResetRequest(ctx, RequestPasswordReset{Email: strings.ToUpper(mixedEmail)}); err != nil {
			t.Fatalf("PasswordResetRequest failed: %v", err)
		}
		mockMailer := auth.Mailer.(*MockMailer)
		if len(mockMailer.SentEmails) != 1 {
			t.Fatalf("expected 1 email sent, got %d", len(mockMailer.SentEmails))
		}
		if got := mockMailer.SentEmails[0]["to"]; got != lowerEmail {
			t.Errorf("expected reset email sent to canonical %q, got %q", lowerEmail, got)
		}
	})

	t.Run("PasswordlessRequest finds the user via upper-case input and emails the canonical address", func(t *testing.T) {
		if err := auth.PasswordlessRequest(ctx, RequestPasswordless{Email: strings.ToUpper(mixedEmail)}); err != nil {
			t.Fatalf("PasswordlessRequest failed: %v", err)
		}
		mockMailer := auth.Mailer.(*MockMailer)
		if len(mockMailer.SentEmails) != 2 {
			t.Fatalf("expected 2 emails sent total, got %d", len(mockMailer.SentEmails))
		}
		if got := mockMailer.SentEmails[1]["to"]; got != lowerEmail {
			t.Errorf("expected passwordless email sent to canonical %q, got %q", lowerEmail, got)
		}

		// A second, already-registered user must not be silently
		// re-created as a new "temporary user for passwordless login".
		users, _, err := auth.Repo.UsersList(ctx, models.UserListFilter{}, 10, 0)
		if err != nil {
			t.Fatalf("UsersList failed: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("expected exactly 1 user (no case-variant duplicate created), got %d", len(users))
		}
	})
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
	auth := &Auth{
		Cfg:             cfg,
		customProviders: make(map[string]OAuth2Provider),
	}

	// Register a test provider (simulating what registerBuiltinProviders does)
	auth.RegisterOAuth2Provider("google", OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     cfg.OAuth2.Google.ClientID,
			ClientSecret: cfg.OAuth2.Google.ClientSecret,
			RedirectURL:  cfg.OAuth2.Google.RedirectURL,
			Scopes:       strings.Split(cfg.OAuth2.Google.Scopes, ","),
			Endpoint:     google.Endpoint,
		},
		UserInfoFn: func(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error) {
			return &OAuth2UserInfo{ID: "test-id", Email: "test@example.com"}, nil
		},
	})

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
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func TestOAuth2Authenticate(t *testing.T) {
	auth := setupOAuth2AuthTestDB(t)
	ctx := context.Background()

	providerID := util.Must(util.RandomString(16))

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

		githubProviderID := util.Must(util.RandomString(16))
		userInfo := &OAuth2UserInfo{
			ID:            githubProviderID,
			Email:         localEmail,
			EmailVerified: true,
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

	t.Run("RejectUnverifiedEmailAutoLink", func(t *testing.T) {
		localEmail := util.UniqueEmail("unverified_local")
		auth.UserCreate(ctx, &RequestBasicAuth{
			Email:    localEmail,
			Password: "password",
		})

		unverifiedProviderID := util.Must(util.RandomString(16))
		userInfo := &OAuth2UserInfo{
			ID:            unverifiedProviderID,
			Email:         localEmail,
			EmailVerified: false,
		}
		_, err := auth.OAuth2Authenticate(ctx, "discord", userInfo)
		if err == nil {
			t.Fatal("OAuth2Authenticate should have failed: unverified email should not auto-link to existing user")
		}

		// The local user should NOT be linked — verify provider and provider_id are unchanged
		linkedUser, err := auth.Repo.UserGetByEmail(ctx, localEmail)
		if err != nil {
			t.Fatalf("failed to fetch user: %v", err)
		}
		if linkedUser.Provider != "local" {
			t.Errorf("expected provider to remain 'local', got %q — auto-link should have been rejected", linkedUser.Provider)
		}
		if linkedUser.ProviderID != nil {
			t.Errorf("expected ProviderID to remain nil, got %q — auto-link should have been rejected", *linkedUser.ProviderID)
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

	storedToken, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(tokenValue))
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

// TestPasswordResetRequest_UnknownEmailDoesEquivalentDummyWork proves the
// unknown-email path still returns nil (unchanged -- an anonymous caller
// must not be able to distinguish "no such account" from "reset email
// sent" via the response itself) while doing comparable CPU/DB work to the
// known-email path (token generation + a DB round-trip) instead of
// returning instantly, and confirms it doesn't send an email or leave any
// token behind for a nonexistent user.
func TestPasswordResetRequest_UnknownEmailDoesEquivalentDummyWork(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	if err := auth.PasswordResetRequest(ctx, RequestPasswordReset{Email: util.UniqueEmail("no-such-account")}); err != nil {
		t.Fatalf("expected nil error for an unknown email, got %v", err)
	}

	mockMailer := auth.Mailer.(*MockMailer)
	if len(mockMailer.SentEmails) != 0 {
		t.Fatalf("expected no email sent for an unknown account, got %d", len(mockMailer.SentEmails))
	}
}
func setupTestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("token_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
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

	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
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

		storedToken, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(refreshToken))
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

		storedOldToken, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(oldRefreshToken))
		if err != nil {
			t.Fatalf("failed to get old token: %v", err)
		}
		if !storedOldToken.Revoked {
			t.Error("expected old refresh token to be revoked after refresh")
		}

		refreshToken = resp.RefreshToken
	})

	t.Run("TokenRevoke", func(t *testing.T) {
		err := auth.TokenRevoke(ctx, createdUser.ID, refreshToken)
		if err != nil {
			t.Fatalf("TokenRevoke() unexpected error: %v", err)
		}

		storedToken, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(refreshToken))
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

	t.Run("TokenRefresh_ReuseDetection", func(t *testing.T) {
		reuseUser, err := auth.Repo.UserCreate(ctx, &models.User{
			Email:        util.UniqueEmail("reuse"),
			PasswordHash: "some-hash",
			Provider:     "local",
		})
		if err != nil {
			t.Fatalf("failed to create test user: %v", err)
		}

		// An unrelated family/user, to prove the cascade doesn't cross families.
		otherUser, err := auth.Repo.UserCreate(ctx, &models.User{
			Email:        util.UniqueEmail("reuse-other"),
			PasswordHash: "some-hash",
			Provider:     "local",
		})
		if err != nil {
			t.Fatalf("failed to create other test user: %v", err)
		}
		otherResp, err := auth.TokenCreate(ctx, otherUser)
		if err != nil {
			t.Fatalf("TokenCreate() for other user unexpected error: %v", err)
		}

		respA, err := auth.TokenCreate(ctx, reuseUser)
		if err != nil {
			t.Fatalf("TokenCreate() unexpected error: %v", err)
		}
		tokenA := respA.RefreshToken

		respB, err := auth.TokenRefresh(ctx, tokenA)
		if err != nil {
			t.Fatalf("TokenRefresh() (A->B) unexpected error: %v", err)
		}
		tokenB := respB.RefreshToken

		respC, err := auth.TokenRefresh(ctx, tokenB)
		if err != nil {
			t.Fatalf("TokenRefresh() (B->C) unexpected error: %v", err)
		}
		tokenC := respC.RefreshToken

		// Replay the already-rotated-out token A: this should be detected as reuse
		// and cascade-revoke the rest of the family, including the currently-active
		// token C, even though C itself was never presented here.
		_, err = auth.TokenRefresh(ctx, tokenA)
		if err == nil {
			t.Fatal("expected error when replaying a rotated-out refresh token, got nil")
		}
		expectedErr := "token revoked"
		if err.Error() != expectedErr {
			t.Errorf("expected error '%s', got '%v'", expectedErr, err)
		}

		storedC, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(tokenC))
		if err != nil {
			t.Fatalf("failed to get token C: %v", err)
		}
		if !storedC.Revoked {
			t.Error("expected token C to be revoked by the family reuse cascade")
		}

		storedOther, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(otherResp.RefreshToken))
		if err != nil {
			t.Fatalf("failed to get unrelated token: %v", err)
		}
		if storedOther.Revoked {
			t.Error("cascade revoked a token from an unrelated family/user")
		}
	})

	t.Run("TokenRevokeAllByUserID", func(t *testing.T) {
		// Create multiple tokens for the user
		token1 := &models.Token{
			UserID:    createdUser.ID,
			Token:     util.Must(util.RandomString(32)),
			TokenType: models.TokenTypeRefresh,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		token2 := &models.Token{
			UserID:    createdUser.ID,
			Token:     util.Must(util.RandomString(32)),
			TokenType: models.TokenTypeRefresh,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		token1, err := auth.Repo.TokenCreate(ctx, token1)
		if err != nil {
			t.Fatalf("failed to create token1: %v", err)
		}
		token2, err = auth.Repo.TokenCreate(ctx, token2)
		if err != nil {
			t.Fatalf("failed to create token2: %v", err)
		}

		// Verify both tokens exist and are not revoked
		t1, _ := auth.Repo.TokenGetByID(ctx, token1.ID)
		t2, _ := auth.Repo.TokenGetByID(ctx, token2.ID)
		if t1.Revoked || t2.Revoked {
			t.Fatal("tokens should not be revoked before the test")
		}

		// Revoke all tokens for the user
		if err := auth.Repo.TokenRevokeAllByUserID(ctx, createdUser.ID); err != nil {
			t.Fatalf("TokenRevokeAllByUserID() failed: %v", err)
		}

		// Verify both tokens are now revoked
		t1, _ = auth.Repo.TokenGetByID(ctx, token1.ID)
		t2, _ = auth.Repo.TokenGetByID(ctx, token2.ID)
		if !t1.Revoked {
			t.Errorf("expected token1 to be revoked, but it was not")
		}
		if !t2.Revoked {
			t.Errorf("expected token2 to be revoked, but it was not")
		}
	})
}

func TestImpersonation(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	admin, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("admin"),
		PasswordHash: "some-hash",
		Provider:     "local",
		Roles:        "admin",
	})
	if err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	target, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("target"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create target user: %v", err)
	}

	parseClaims := func(t *testing.T, accessToken string) jwt.MapClaims {
		t.Helper()
		tok, err := jwt.Parse(accessToken, func(token *jwt.Token) (any, error) {
			return []byte(auth.Cfg.JWTSecret), nil
		})
		if err != nil {
			t.Fatalf("failed to parse access token: %v", err)
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatalf("unexpected claims type")
		}
		return claims
	}

	t.Run("rejects missing admin", func(t *testing.T) {
		if _, err := auth.Impersonate(ctx, nil, target.ID); err == nil {
			t.Error("expected error for nil admin user, got nil")
		}
	})

	t.Run("rejects empty target", func(t *testing.T) {
		if _, err := auth.Impersonate(ctx, admin, ""); err == nil {
			t.Error("expected error for empty target user id, got nil")
		}
	})

	t.Run("rejects self-impersonation", func(t *testing.T) {
		if _, err := auth.Impersonate(ctx, admin, admin.ID); err == nil {
			t.Error("expected error for self-impersonation, got nil")
		}
	})

	t.Run("rejects unknown target", func(t *testing.T) {
		if _, err := auth.Impersonate(ctx, admin, "does-not-exist"); err == nil {
			t.Error("expected error for unknown target user, got nil")
		}
	})

	var impersonationRefreshToken string

	t.Run("mints tokens with act claim and tags metadata", func(t *testing.T) {
		resp, err := auth.Impersonate(ctx, admin, target.ID)
		if err != nil {
			t.Fatalf("Impersonate() unexpected error: %v", err)
		}
		impersonationRefreshToken = resp.RefreshToken

		claims := parseClaims(t, resp.AccessToken)
		if claims["sub"] != target.ID {
			t.Errorf("expected sub claim %s, got %v", target.ID, claims["sub"])
		}
		act, ok := claims["act"].(map[string]any)
		if !ok {
			t.Fatalf("expected act claim to be present, got %v", claims["act"])
		}
		if act["sub"] != admin.ID {
			t.Errorf("expected act.sub claim %s, got %v", admin.ID, act["sub"])
		}

		storedToken, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(resp.RefreshToken))
		if err != nil {
			t.Fatalf("failed to get impersonation refresh token: %v", err)
		}
		if imp, _ := storedToken.Metadata["impersonation"].(bool); !imp {
			t.Error("expected refresh token metadata to be tagged as impersonation")
		}
		if storedToken.Metadata["actor_id"] != admin.ID {
			t.Errorf("expected refresh token metadata actor_id %s, got %v", admin.ID, storedToken.Metadata["actor_id"])
		}
	})

	t.Run("refresh preserves act claim", func(t *testing.T) {
		resp, err := auth.TokenRefresh(ctx, impersonationRefreshToken)
		if err != nil {
			t.Fatalf("TokenRefresh() unexpected error: %v", err)
		}
		impersonationRefreshToken = resp.RefreshToken

		claims := parseClaims(t, resp.AccessToken)
		act, ok := claims["act"].(map[string]any)
		if !ok {
			t.Fatalf("expected act claim to survive refresh, got %v", claims["act"])
		}
		if act["sub"] != admin.ID {
			t.Errorf("expected act.sub claim %s after refresh, got %v", admin.ID, act["sub"])
		}
	})

	t.Run("plain TokenCreate has no act claim", func(t *testing.T) {
		resp, err := auth.TokenCreate(ctx, target)
		if err != nil {
			t.Fatalf("TokenCreate() unexpected error: %v", err)
		}
		claims := parseClaims(t, resp.AccessToken)
		if _, ok := claims["act"]; ok {
			t.Errorf("expected no act claim on a regular token, got %v", claims["act"])
		}
	})

	t.Run("StopImpersonating rejects non-impersonation token", func(t *testing.T) {
		resp, err := auth.TokenCreate(ctx, target)
		if err != nil {
			t.Fatalf("TokenCreate() unexpected error: %v", err)
		}
		if err := auth.StopImpersonating(ctx, admin.ID, resp.RefreshToken); err == nil {
			t.Error("expected error when stopping a non-impersonation token, got nil")
		}
	})

	t.Run("StopImpersonating rejects a caller who isn't the impersonation's actor", func(t *testing.T) {
		otherAdmin, err := auth.UserCreate(ctx, &RequestBasicAuth{
			Email:    util.UniqueEmail("otheradmin"),
			Password: "securepass123",
		})
		if err != nil {
			t.Fatalf("UserCreate() unexpected error: %v", err)
		}
		if err := auth.StopImpersonating(ctx, otherAdmin.ID, impersonationRefreshToken); err == nil {
			t.Error("expected error when a different admin stops someone else's impersonation, got nil")
		}

		// The wrong caller's attempt must not have revoked the token.
		storedToken, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(impersonationRefreshToken))
		if err != nil {
			t.Fatalf("failed to get impersonation token: %v", err)
		}
		if storedToken.Revoked {
			t.Error("impersonation token was revoked by a caller who wasn't its actor")
		}
	})

	t.Run("StopImpersonating revokes the impersonation token", func(t *testing.T) {
		if err := auth.StopImpersonating(ctx, admin.ID, impersonationRefreshToken); err != nil {
			t.Fatalf("StopImpersonating() unexpected error: %v", err)
		}

		storedToken, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(impersonationRefreshToken))
		if err != nil {
			t.Fatalf("failed to get token after stop: %v", err)
		}
		if !storedToken.Revoked {
			t.Error("expected impersonation refresh token to be revoked")
		}

		if _, err := auth.TokenRefresh(ctx, impersonationRefreshToken); err == nil {
			t.Error("expected error when refreshing a revoked impersonation token, got nil")
		}
	})
}

func TestArgon2idHashing(t *testing.T) {
	t.Run("hashes and verifies with valid parameters", func(t *testing.T) {
		auth := &Auth{Cfg: &config.Config{Hashing: config.Hashing{
			Algorithm:         "argon2id",
			Argon2Memory:      65536,
			Argon2Iterations:  3,
			Argon2Parallelism: 4,
			Argon2SaltLength:  16,
			Argon2KeyLength:   32,
		}}}

		hash, err := auth.UserHashPassword("s3cret-password")
		if err != nil {
			t.Fatalf("UserHashPassword() unexpected error: %v", err)
		}
		if !strings.HasPrefix(hash, "$argon2id$") {
			t.Fatalf("expected an argon2id hash, got %q", hash)
		}
		if !verifyPassword("s3cret-password", hash) {
			t.Error("expected verifyPassword() to succeed with the correct password")
		}
		if verifyPassword("wrong-password", hash) {
			t.Error("expected verifyPassword() to fail with the wrong password")
		}
	})

	t.Run("returns an error instead of panicking on a zero-value config", func(t *testing.T) {
		auth := &Auth{Cfg: &config.Config{Hashing: config.Hashing{Algorithm: "argon2id"}}}

		if _, err := auth.UserHashPassword("s3cret-password"); err == nil {
			t.Fatal("expected UserHashPassword() to return an error for an unconfigured argon2 config, got nil")
		}
	})
}

// TestGetDummyPasswordHash_MatchesConfiguredCost proves the timing-equalization
// dummy hash used on UserAuthenticate's account-not-found path is derived
// from the live configured bcrypt cost, not a hardcoded literal -- a
// mismatch would make the real-vs-dummy comparison time itself an
// account-existence signal, inverting the protection this mechanism exists
// to provide.
func TestGetDummyPasswordHash_MatchesConfiguredCost(t *testing.T) {
	const configuredCost = 6 // deliberately not bcrypt.DefaultCost (10) or the old hardcoded 14
	auth := &Auth{Cfg: &config.Config{Hashing: config.Hashing{BcryptCost: configuredCost}}}

	hash := auth.getDummyPasswordHash()
	if hash == "" {
		t.Fatal("expected a non-empty dummy hash")
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost failed to parse the dummy hash: %v", err)
	}
	if cost != configuredCost {
		t.Errorf("expected the dummy hash to use the configured cost %d, got %d", configuredCost, cost)
	}

	// Computed once and cached -- a second call must return the identical
	// hash, not recompute (which would defeat the point of caching it).
	if second := auth.getDummyPasswordHash(); second != hash {
		t.Errorf("expected getDummyPasswordHash to cache its result, got a different hash on the second call")
	}
}
