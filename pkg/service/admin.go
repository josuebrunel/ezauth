package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

const (
	defaultUsersListLimit   = 20
	maxUsersListLimit       = 100
	defaultAuthHistoryLimit = 50
	maxAuthHistoryLimit     = 200
)

// ErrInvalidUserStatusFilter is returned when ListUsersOptions.Status isn't
// one of models.UserStatusActive, models.UserStatusLocked, or
// models.UserStatusSuspended.
var ErrInvalidUserStatusFilter = errors.New("invalid status filter")

// ListUsersOptions defines the search/filter/pagination parameters for UsersList.
type ListUsersOptions struct {
	// Search matches (substring) against email or username.
	Search string

	// Status filters by account status: models.UserStatusActive,
	// models.UserStatusLocked, or models.UserStatusSuspended. Empty means no filter.
	Status string

	// CreatedAfter/CreatedBefore filter by account creation time (inclusive).
	CreatedAfter  *time.Time
	CreatedBefore *time.Time

	// LastActiveAfter/LastActiveBefore filter by last-active time (inclusive).
	LastActiveAfter  *time.Time
	LastActiveBefore *time.Time

	Limit  int
	Offset int
}

// ListUsersResult is a page of users, with sensitive fields stripped.
type ListUsersResult struct {
	Users   []*models.User `json:"users"`
	HasMore bool           `json:"has_more"`
}

// UsersList lists/searches/filters users, most recently created first. ezauth
// performs no authorization check here — same stance as Impersonate — the
// caller is responsible for verifying the requester is allowed to list users
// (e.g. via caller.HasRole("admin")).
func (a *Auth) UsersList(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error) {
	switch opts.Status {
	case "", models.UserStatusActive, models.UserStatusLocked, models.UserStatusSuspended:
	default:
		return nil, ErrInvalidUserStatusFilter
	}

	limit := opts.Limit
	if limit <= 0 || limit > maxUsersListLimit {
		limit = defaultUsersListLimit
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	filter := models.UserListFilter{
		Search:           strings.TrimSpace(opts.Search),
		Status:           opts.Status,
		CreatedAfter:     opts.CreatedAfter,
		CreatedBefore:    opts.CreatedBefore,
		LastActiveAfter:  opts.LastActiveAfter,
		LastActiveBefore: opts.LastActiveBefore,
	}

	users, hasMore, err := a.Repo.UsersList(ctx, filter, limit, offset)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		u.Sanitize()
	}
	return &ListUsersResult{Users: users, HasMore: hasMore}, nil
}

// UserSuspend deactivates a user's account (clearing IsActive with no
// LockedUntil expiry, so it does not auto-recover the way a brute-force
// lockout does — see UserAuthenticate/ErrAccountDisabled). ezauth performs no
// authorization check here; the caller is responsible for verifying the
// requester may suspend accounts.
func (a *Auth) UserSuspend(ctx context.Context, userID string) (*models.User, error) {
	return a.Repo.UserSetLockoutState(ctx, userID, 0, nil, false)
}

// UserReactivate re-enables a suspended or locked-out account, also clearing
// any failed-login/lockout bookkeeping. ezauth performs no authorization
// check here; the caller is responsible for verifying the requester may
// reactivate accounts.
func (a *Auth) UserReactivate(ctx context.Context, userID string) (*models.User, error) {
	return a.Repo.UserSetLockoutState(ctx, userID, 0, nil, true)
}

// AuthHistoryEntry summarizes one authentication-related token event for a
// user (e.g. a login, a password reset, an MFA step-up) without exposing the
// raw token value.
type AuthHistoryEntry struct {
	TokenType string    `json:"token_type"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// UserAuthHistory returns a user's most recent authentication-related token
// events, most recent first. This is a lightweight proxy for a proper audit
// log (ezauth doesn't persist one), built from the same Tokens table every
// other feature already writes to.
func (a *Auth) UserAuthHistory(ctx context.Context, userID string, limit int) ([]AuthHistoryEntry, error) {
	if limit <= 0 || limit > maxAuthHistoryLimit {
		limit = defaultAuthHistoryLimit
	}

	tokens, err := a.Repo.TokenListByUserID(ctx, userID, limit)
	if err != nil {
		return nil, err
	}

	entries := make([]AuthHistoryEntry, 0, len(tokens))
	for _, tok := range tokens {
		entries = append(entries, AuthHistoryEntry{
			TokenType: tok.TokenType,
			CreatedAt: tok.CreatedAt,
			ExpiresAt: tok.ExpiresAt,
			Revoked:   tok.Revoked,
		})
	}
	return entries, nil
}
