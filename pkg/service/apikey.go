package service

import (
	"context"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

// CreateAPIKey mints a new API key for userID. scopes limits the key to
// those actions (checked via RequireAPIKeyScope middleware); an empty/nil
// scopes list creates an unscoped key with full account access, matching
// every API key issued before per-key scoping existed. The returned
// Token's Token field is the raw key value — it is stored and looked up
// verbatim (like refresh tokens), so surface it to the caller now, since
// it can't be recovered later.
func (a *Auth) CreateAPIKey(ctx context.Context, userID string, scopes []string) (*models.Token, error) {
	key, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate api key", "user_id", userID, "err", err)
		return nil, err
	}

	metadata := models.JSONMap{}
	if len(scopes) > 0 {
		metadata["scopes"] = scopes
	}

	token := &models.Token{
		UserID:    userID,
		Token:     key,
		TokenType: models.TokenTypeApiKey,
		ExpiresAt: time.Time{}, // API keys don't expire by default
		Revoked:   false,
		Metadata:  metadata,
	}

	created, err := a.Repo.TokenCreate(ctx, token)
	if err != nil {
		xlog.Error("failed to create api key", "user_id", userID, "err", err)
		return nil, err
	}
	xlog.Info("api key created", "user_id", userID, "token_id", created.ID, "scoped", len(scopes) > 0)
	return created, nil
}

// RevokeAPIKey revokes an API key by its token ID (see ListAPIKeys).
func (a *Auth) RevokeAPIKey(ctx context.Context, id string) error {
	if err := a.Repo.TokenRevoke(ctx, id); err != nil {
		xlog.Error("failed to revoke api key", "token_id", id, "err", err)
		return err
	}
	xlog.Info("api key revoked", "token_id", id)
	return nil
}

// ListAPIKeys lists a user's API keys.
func (a *Auth) ListAPIKeys(ctx context.Context, userID string) ([]*models.Token, error) {
	return a.Repo.TokenListByUserIDAndType(ctx, userID, models.TokenTypeApiKey)
}
