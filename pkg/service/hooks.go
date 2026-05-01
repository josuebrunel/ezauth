package service

import (
	"context"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// Hooks defines a set of function fields that can be used to react to authentication events.
type Hooks struct {
	OnUserCreated            func(ctx context.Context, user *models.User) error
	OnUserUpdated            func(ctx context.Context, user *models.User) error
	OnUserDeleted            func(ctx context.Context, user *models.User) error
	OnUserSignedIn           func(ctx context.Context, user *models.User) error
	OnUserSignedOut          func(ctx context.Context, user *models.User) error
	OnUserTokenRefreshed     func(ctx context.Context, user *models.User) error
	OnPasswordResetRequested func(ctx context.Context, user *models.User) error
	OnPasswordResetConfirmed func(ctx context.Context, user *models.User) error
	OnPasswordlessRequested  func(ctx context.Context, user *models.User) error
	OnPasswordlessSignedIn   func(ctx context.Context, user *models.User) error
	OnOAuth2SignedIn         func(ctx context.Context, user *models.User, provider string) error
	OnOAuth2Created          func(ctx context.Context, user *models.User, provider string) error
}

// CallHook is a nil-safe helper to call a hook function.
func CallHook[T any](fn func(context.Context, T) error, ctx context.Context, arg T) error {
	if fn == nil {
		return nil
	}
	return fn(ctx, arg)
}

// CallHookWithProvider is a nil-safe helper to call a hook function with an additional provider argument.
func CallHookWithProvider[T any](fn func(context.Context, T, string) error, ctx context.Context, arg T, provider string) error {
	if fn == nil {
		return nil
	}
	return fn(ctx, arg, provider)
}
