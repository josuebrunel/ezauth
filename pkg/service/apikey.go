package service

import (
	"context"
	"errors"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
)

// ErrAPIKeyNotFound is returned when an API key doesn't exist, doesn't
// belong to the caller, or isn't actually an API key.
var ErrAPIKeyNotFound = errors.New("api key not found")

// defaultAPIKeyTTL backstops Cfg.APIKeyDefaultTTL for a hand-built
// config.Config{} that bypasses LoadConfig's default:"87600h" env tag
// (common in tests, or a caller loading config another way) -- a zero TTL
// would otherwise mint a key that's already expired.
const defaultAPIKeyTTL = 10 * 365 * 24 * time.Hour

// APIKeyCreate mints a new API key for userID. scopes limits the key to
// those actions (checked via RequireAPIKeyScope middleware); an empty/nil
// scopes list creates an unscoped key with full account access, matching
// every API key issued before per-key scoping existed. ttl bounds how long
// the key is valid for; pass 0 to use Cfg.APIKeyDefaultTTL (10 years by
// default, matching every prior release -- API keys are meant for
// long-lived machine-to-machine use, not short sessions). The returned
// Token's Token field is the raw key value — only its hash is stored/looked
// up (see util.HashToken), so surface the raw value to the caller now,
// since it can't be recovered later.
func (a *Auth) APIKeyCreate(ctx context.Context, userID string, scopes []string, ttl time.Duration) (*models.Token, error) {
	key, err := a.generateRefreshToken()
	if err != nil {
		xlog.Error("failed to generate api key", "user_id", userID, "err", err)
		return nil, err
	}

	metadata := models.JSONMap{}
	if len(scopes) > 0 {
		metadata["scopes"] = scopes
	}

	if ttl <= 0 {
		ttl = a.Cfg.APIKeyDefaultTTL
	}
	if ttl <= 0 {
		ttl = defaultAPIKeyTTL
	}

	token := &models.Token{
		UserID:    userID,
		Token:     util.HashToken(key),
		TokenType: models.TokenTypeApiKey,
		ExpiresAt: time.Now().Add(ttl),
		Revoked:   false,
		Metadata:  metadata,
	}

	created, err := a.Repo.TokenCreate(ctx, token)
	if err != nil {
		xlog.Error("failed to create api key", "user_id", userID, "err", err)
		return nil, err
	}
	// created.Token is the hash just stored -- restore the raw value the
	// caller actually needs to display (it's never recoverable from the
	// hash once this returns).
	created.Token = key
	xlog.Info("api key created", "user_id", userID, "token_id", created.ID, "scoped", len(scopes) > 0)
	return created, nil
}

// APIKeyRevoke revokes one of userID's API keys by its token ID (see
// APIKeysList). Returns ErrAPIKeyNotFound if the key doesn't exist, isn't
// an API key, or belongs to a different user -- mirrors RevokeSession's
// ownership check so self-service revocation can't be used to revoke
// another user's key by guessing its ID.
func (a *Auth) APIKeyRevoke(ctx context.Context, userID, id string) error {
	tok, err := a.Repo.TokenGetByID(ctx, id)
	if err != nil || tok.UserID != userID || tok.TokenType != models.TokenTypeApiKey {
		return ErrAPIKeyNotFound
	}

	if err := a.Repo.TokenRevoke(ctx, id); err != nil {
		xlog.Error("failed to revoke api key", "user_id", userID, "token_id", id, "err", err)
		return err
	}
	xlog.Info("api key revoked", "user_id", userID, "token_id", id)
	return nil
}

// APIKeyInfo describes one of a user's API keys without exposing the raw
// key value -- mirrors SessionInfo's rationale: the value is shown once,
// at APIKeyCreate time, and never again.
type APIKeyInfo struct {
	ID        string    `json:"id"`
	Scopes    []string  `json:"scopes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// APIKeysList lists a user's API keys, most recently created first.
func (a *Auth) APIKeysList(ctx context.Context, userID string) ([]APIKeyInfo, error) {
	tokens, err := a.Repo.TokenListByUserIDAndType(ctx, userID, models.TokenTypeApiKey)
	if err != nil {
		return nil, err
	}

	keys := make([]APIKeyInfo, 0, len(tokens))
	for _, tok := range tokens {
		keys = append(keys, APIKeyInfo{
			ID:        tok.ID,
			Scopes:    tok.Scopes(),
			CreatedAt: tok.CreatedAt,
			ExpiresAt: tok.ExpiresAt,
			Revoked:   tok.Revoked,
		})
	}
	return keys, nil
}
