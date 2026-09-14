package service

import (
	"context"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func TestAPIKeys(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("apikey"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	t.Run("APIKeyCreate_Unscoped", func(t *testing.T) {
		token, err := auth.APIKeyCreate(ctx, user.ID, nil, 0)
		if err != nil {
			t.Fatalf("APIKeyCreate() unexpected error: %v", err)
		}
		if token.Token == "" {
			t.Error("expected a non-empty key value")
		}
		if token.TokenType != models.TokenTypeApiKey {
			t.Errorf("expected token type %s, got %s", models.TokenTypeApiKey, token.TokenType)
		}
		if !token.HasScope("anything") {
			t.Error("expected an unscoped key to have access to any scope")
		}

		stored, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(token.Token))
		if err != nil {
			t.Fatalf("failed to get api key from db: %v", err)
		}
		if stored.UserID != user.ID {
			t.Errorf("expected user id %s, got %s", user.ID, stored.UserID)
		}
		if !stored.ExpiresAt.After(time.Now().AddDate(5, 0, 0)) {
			t.Errorf("expected api key to expire far in the future (effectively never), got %v", stored.ExpiresAt)
		}
	})

	t.Run("APIKeyCreate_Scoped", func(t *testing.T) {
		token, err := auth.APIKeyCreate(ctx, user.ID, []string{"posts:write"}, 0)
		if err != nil {
			t.Fatalf("APIKeyCreate() unexpected error: %v", err)
		}
		if !token.HasScope("posts:write") {
			t.Error("expected key to have the posts:write scope")
		}
		if token.HasScope("posts:delete") {
			t.Error("expected key to not have the posts:delete scope")
		}

		// Confirm the scope survives a DB round-trip (Metadata becomes []any after Scan).
		stored, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(token.Token))
		if err != nil {
			t.Fatalf("failed to get api key from db: %v", err)
		}
		if !stored.HasScope("posts:write") {
			t.Error("expected scope to survive a DB round-trip")
		}
		if stored.HasScope("posts:delete") {
			t.Error("expected the key to remain scoped after a DB round-trip")
		}
	})

	t.Run("APIKeysList", func(t *testing.T) {
		keys, err := auth.APIKeysList(ctx, user.ID)
		if err != nil {
			t.Fatalf("APIKeysList() unexpected error: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("expected 2 api keys, got %d", len(keys))
		}
		for _, k := range keys {
			if k.ID == "" {
				t.Errorf("expected a non-empty key id")
			}
		}
	})

	t.Run("APIKeyRevoke", func(t *testing.T) {
		token, err := auth.APIKeyCreate(ctx, user.ID, nil, 0)
		if err != nil {
			t.Fatalf("APIKeyCreate() unexpected error: %v", err)
		}

		if err := auth.APIKeyRevoke(ctx, user.ID, token.ID); err != nil {
			t.Fatalf("APIKeyRevoke() unexpected error: %v", err)
		}

		stored, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(token.Token))
		if err != nil {
			t.Fatalf("failed to get api key from db: %v", err)
		}
		if !stored.Revoked {
			t.Error("expected api key to be revoked")
		}
	})

	t.Run("APIKeyRevoke_WrongOwner", func(t *testing.T) {
		other, err := auth.Repo.UserCreate(ctx, &models.User{
			Email:        util.UniqueEmail("apikey-other"),
			PasswordHash: "some-hash",
			Provider:     "local",
		})
		if err != nil {
			t.Fatalf("failed to create test user: %v", err)
		}

		token, err := auth.APIKeyCreate(ctx, user.ID, nil, 0)
		if err != nil {
			t.Fatalf("APIKeyCreate() unexpected error: %v", err)
		}

		if err := auth.APIKeyRevoke(ctx, other.ID, token.ID); err != ErrAPIKeyNotFound {
			t.Fatalf("expected ErrAPIKeyNotFound revoking another user's key, got %v", err)
		}

		stored, err := auth.Repo.TokenGetByToken(ctx, util.HashToken(token.Token))
		if err != nil {
			t.Fatalf("failed to get api key from db: %v", err)
		}
		if stored.Revoked {
			t.Error("expected api key to remain active after a wrong-owner revoke attempt")
		}
	})
}

// TestAPIKeyCreate_TTL proves the ttl parameter controls the key's expiry
// (an explicit TTL, Cfg.APIKeyDefaultTTL, and the built-in fallback for a
// hand-built config.Config{} that leaves APIKeyDefaultTTL at its zero
// value), rather than the fixed 10-year expiry every prior release
// hardcoded. See #210.
func TestAPIKeyCreate_TTL(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()
	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("apikeyttl"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// toleranceUpper allows for MySQL's DATETIME columns (no fractional-
	// seconds precision) rounding a written timestamp up to the nearest
	// second on read-back, which can otherwise make gotTTL appear slightly
	// *larger* than the requested duration.
	const toleranceUpper = 2 * time.Second

	t.Run("explicit ttl is honored", func(t *testing.T) {
		token, err := auth.APIKeyCreate(ctx, user.ID, nil, time.Hour)
		if err != nil {
			t.Fatalf("APIKeyCreate() unexpected error: %v", err)
		}
		gotTTL := time.Until(token.ExpiresAt)
		if gotTTL < 55*time.Minute || gotTTL > time.Hour+toleranceUpper {
			t.Errorf("expected TTL close to the configured 1h, got %v", gotTTL)
		}
	})

	t.Run("zero ttl uses Cfg.APIKeyDefaultTTL", func(t *testing.T) {
		auth.Cfg.APIKeyDefaultTTL = 24 * time.Hour
		defer func() { auth.Cfg.APIKeyDefaultTTL = 0 }()

		token, err := auth.APIKeyCreate(ctx, user.ID, nil, 0)
		if err != nil {
			t.Fatalf("APIKeyCreate() unexpected error: %v", err)
		}
		gotTTL := time.Until(token.ExpiresAt)
		if gotTTL < 23*time.Hour || gotTTL > 24*time.Hour+toleranceUpper {
			t.Errorf("expected TTL close to the configured 24h default, got %v", gotTTL)
		}
	})

	t.Run("zero ttl and zero Cfg.APIKeyDefaultTTL falls back to 10 years", func(t *testing.T) {
		auth.Cfg.APIKeyDefaultTTL = 0
		token, err := auth.APIKeyCreate(ctx, user.ID, nil, 0)
		if err != nil {
			t.Fatalf("APIKeyCreate() unexpected error: %v", err)
		}
		gotTTL := time.Until(token.ExpiresAt)
		if gotTTL < defaultAPIKeyTTL-time.Hour || gotTTL > defaultAPIKeyTTL+toleranceUpper {
			t.Errorf("expected TTL close to the %v fallback, got %v", defaultAPIKeyTTL, gotTTL)
		}
	})
}
