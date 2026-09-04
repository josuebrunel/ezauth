package service

import (
	"context"
	"testing"

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

	t.Run("CreateAPIKey_Unscoped", func(t *testing.T) {
		token, err := auth.CreateAPIKey(ctx, user.ID, nil)
		if err != nil {
			t.Fatalf("CreateAPIKey() unexpected error: %v", err)
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

		stored, err := auth.Repo.TokenGetByToken(ctx, token.Token)
		if err != nil {
			t.Fatalf("failed to get api key from db: %v", err)
		}
		if stored.UserID != user.ID {
			t.Errorf("expected user id %s, got %s", user.ID, stored.UserID)
		}
		if !stored.ExpiresAt.IsZero() {
			t.Errorf("expected api key to never expire, got %v", stored.ExpiresAt)
		}
	})

	t.Run("CreateAPIKey_Scoped", func(t *testing.T) {
		token, err := auth.CreateAPIKey(ctx, user.ID, []string{"posts:write"})
		if err != nil {
			t.Fatalf("CreateAPIKey() unexpected error: %v", err)
		}
		if !token.HasScope("posts:write") {
			t.Error("expected key to have the posts:write scope")
		}
		if token.HasScope("posts:delete") {
			t.Error("expected key to not have the posts:delete scope")
		}

		// Confirm the scope survives a DB round-trip (Metadata becomes []any after Scan).
		stored, err := auth.Repo.TokenGetByToken(ctx, token.Token)
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

	t.Run("ListAPIKeys", func(t *testing.T) {
		keys, err := auth.ListAPIKeys(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListAPIKeys() unexpected error: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("expected 2 api keys, got %d", len(keys))
		}
		for _, k := range keys {
			if k.TokenType != models.TokenTypeApiKey {
				t.Errorf("expected only api keys, got token type %s", k.TokenType)
			}
		}
	})

	t.Run("RevokeAPIKey", func(t *testing.T) {
		token, err := auth.CreateAPIKey(ctx, user.ID, nil)
		if err != nil {
			t.Fatalf("CreateAPIKey() unexpected error: %v", err)
		}

		if err := auth.RevokeAPIKey(ctx, token.ID); err != nil {
			t.Fatalf("RevokeAPIKey() unexpected error: %v", err)
		}

		stored, err := auth.Repo.TokenGetByToken(ctx, token.Token)
		if err != nil {
			t.Fatalf("failed to get api key from db: %v", err)
		}
		if !stored.Revoked {
			t.Error("expected api key to be revoked")
		}
	})
}
