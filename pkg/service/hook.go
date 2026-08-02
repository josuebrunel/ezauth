package service

import (
	"context"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// Hook defines lifecycle hooks for authentication events.
// Implement this interface to intercept auth events without modifying ezauth internals.
// Embed DefaultHook and override only the methods you need.
type Hook interface {
	// BeforeUserCreated is called before a new user is persisted.
	// Return a non-nil error to abort the operation.
	BeforeUserCreated(ctx context.Context, user *models.User) error

	// AfterUserCreated is called after a new user has been persisted.
	AfterUserCreated(ctx context.Context, user *models.User) error

	// BeforeUserUpdated is called before a user is updated.
	// Return a non-nil error to abort the operation.
	BeforeUserUpdated(ctx context.Context, user *models.User) error

	// AfterUserUpdated is called after a user has been updated.
	AfterUserUpdated(ctx context.Context, user *models.User) error

	// BeforeUserDeleted is called before a user is deleted.
	// Return a non-nil error to abort the operation.
	BeforeUserDeleted(ctx context.Context, user *models.User) error

	// AfterUserDeleted is called after a user has been deleted.
	AfterUserDeleted(ctx context.Context, user *models.User) error

	// AfterUserSignedIn is called after a successful sign-in.
	AfterUserSignedIn(ctx context.Context, user *models.User) error

	// AfterUserSignedOut is called after a successful sign-out.
	AfterUserSignedOut(ctx context.Context, user *models.User) error

	// AfterPasswordResetRequested is called after a password reset has been requested.
	AfterPasswordResetRequested(ctx context.Context, user *models.User) error

	// AfterPasswordResetConfirmed is called after a password reset has been confirmed.
	AfterPasswordResetConfirmed(ctx context.Context, user *models.User) error

	// AfterOAuth2SignedIn is called after a successful OAuth2 sign-in for an existing user.
	AfterOAuth2SignedIn(ctx context.Context, user *models.User, provider string) error

	// AfterOAuth2Created is called after a new user is created via OAuth2.
	AfterOAuth2Created(ctx context.Context, user *models.User, provider string) error

	// AfterImpersonationStarted is called after an admin begins impersonating a target user.
	AfterImpersonationStarted(ctx context.Context, admin *models.User, target *models.User) error

	// AfterImpersonationEnded is called after an impersonation session ends.
	AfterImpersonationEnded(ctx context.Context, admin *models.User, target *models.User) error
}

// DefaultHook is a no-op implementation of Hook.
// Embed it in your struct and override only the methods you need.
type DefaultHook struct{}

func (DefaultHook) BeforeUserCreated(_ context.Context, _ *models.User) error  { return nil }
func (DefaultHook) AfterUserCreated(_ context.Context, _ *models.User) error   { return nil }
func (DefaultHook) BeforeUserUpdated(_ context.Context, _ *models.User) error  { return nil }
func (DefaultHook) AfterUserUpdated(_ context.Context, _ *models.User) error   { return nil }
func (DefaultHook) BeforeUserDeleted(_ context.Context, _ *models.User) error  { return nil }
func (DefaultHook) AfterUserDeleted(_ context.Context, _ *models.User) error   { return nil }
func (DefaultHook) AfterUserSignedIn(_ context.Context, _ *models.User) error  { return nil }
func (DefaultHook) AfterUserSignedOut(_ context.Context, _ *models.User) error { return nil }
func (DefaultHook) AfterPasswordResetRequested(_ context.Context, _ *models.User) error {
	return nil
}
func (DefaultHook) AfterPasswordResetConfirmed(_ context.Context, _ *models.User) error {
	return nil
}
func (DefaultHook) AfterOAuth2SignedIn(_ context.Context, _ *models.User, _ string) error {
	return nil
}
func (DefaultHook) AfterOAuth2Created(_ context.Context, _ *models.User, _ string) error {
	return nil
}
func (DefaultHook) AfterImpersonationStarted(_ context.Context, _ *models.User, _ *models.User) error {
	return nil
}
func (DefaultHook) AfterImpersonationEnded(_ context.Context, _ *models.User, _ *models.User) error {
	return nil
}
