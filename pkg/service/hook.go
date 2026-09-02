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

	// AfterMFAEnabled is called after a user successfully enables TOTP MFA.
	AfterMFAEnabled(ctx context.Context, user *models.User) error

	// AfterMFADisabled is called after a user disables TOTP MFA.
	AfterMFADisabled(ctx context.Context, user *models.User) error

	// AfterLoginFailed is called after a failed login attempt for a known
	// user (wrong password). reason is a short machine-readable cause, e.g.
	// "invalid_password".
	AfterLoginFailed(ctx context.Context, user *models.User, reason string) error

	// AfterAccountLocked is called after a user's account is locked out due
	// to too many consecutive failed login attempts (see
	// Config.AccountLockout).
	AfterAccountLocked(ctx context.Context, user *models.User) error
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
func (DefaultHook) AfterMFAEnabled(_ context.Context, _ *models.User) error  { return nil }
func (DefaultHook) AfterMFADisabled(_ context.Context, _ *models.User) error { return nil }
func (DefaultHook) AfterLoginFailed(_ context.Context, _ *models.User, _ string) error {
	return nil
}
func (DefaultHook) AfterAccountLocked(_ context.Context, _ *models.User) error { return nil }

// auditHook wraps another Hook, persisting an audit-log row (see
// Auth.recordAuditEvent) for each security-relevant lifecycle event before
// delegating to the wrapped hook. Auth.New and Auth.SetHook always install
// one of these as Auth.Hook, so persisted audit logging works regardless of
// whether the consumer registers their own Hook.
type auditHook struct {
	auth *Auth
	next Hook
}

// newAuditHook wraps next (DefaultHook{} if nil) with audit-log persistence.
func newAuditHook(auth *Auth, next Hook) Hook {
	if next == nil {
		next = DefaultHook{}
	}
	return &auditHook{auth: auth, next: next}
}

func (h *auditHook) BeforeUserCreated(ctx context.Context, user *models.User) error {
	return h.next.BeforeUserCreated(ctx, user)
}

func (h *auditHook) AfterUserCreated(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventUserCreated, nil)
	return h.next.AfterUserCreated(ctx, user)
}

func (h *auditHook) BeforeUserUpdated(ctx context.Context, user *models.User) error {
	return h.next.BeforeUserUpdated(ctx, user)
}

func (h *auditHook) AfterUserUpdated(ctx context.Context, user *models.User) error {
	return h.next.AfterUserUpdated(ctx, user)
}

func (h *auditHook) BeforeUserDeleted(ctx context.Context, user *models.User) error {
	return h.next.BeforeUserDeleted(ctx, user)
}

func (h *auditHook) AfterUserDeleted(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventUserDeleted, nil)
	return h.next.AfterUserDeleted(ctx, user)
}

func (h *auditHook) AfterUserSignedIn(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventLoginSucceeded, nil)
	return h.next.AfterUserSignedIn(ctx, user)
}

func (h *auditHook) AfterUserSignedOut(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventLogoutSucceeded, nil)
	return h.next.AfterUserSignedOut(ctx, user)
}

func (h *auditHook) AfterPasswordResetRequested(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventPasswordResetRequested, nil)
	return h.next.AfterPasswordResetRequested(ctx, user)
}

func (h *auditHook) AfterPasswordResetConfirmed(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventPasswordResetConfirmed, nil)
	return h.next.AfterPasswordResetConfirmed(ctx, user)
}

func (h *auditHook) AfterOAuth2SignedIn(ctx context.Context, user *models.User, provider string) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventOAuth2SignedIn, models.JSONMap{"provider": provider})
	return h.next.AfterOAuth2SignedIn(ctx, user, provider)
}

func (h *auditHook) AfterOAuth2Created(ctx context.Context, user *models.User, provider string) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventOAuth2Created, models.JSONMap{"provider": provider})
	return h.next.AfterOAuth2Created(ctx, user, provider)
}

func (h *auditHook) AfterImpersonationStarted(ctx context.Context, admin *models.User, target *models.User) error {
	h.auth.recordAuditEvent(ctx, target.ID, models.AuditEventImpersonationStarted, models.JSONMap{"actor_id": admin.ID})
	return h.next.AfterImpersonationStarted(ctx, admin, target)
}

func (h *auditHook) AfterImpersonationEnded(ctx context.Context, admin *models.User, target *models.User) error {
	h.auth.recordAuditEvent(ctx, target.ID, models.AuditEventImpersonationEnded, models.JSONMap{"actor_id": admin.ID})
	return h.next.AfterImpersonationEnded(ctx, admin, target)
}

func (h *auditHook) AfterMFAEnabled(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventMFAEnabled, nil)
	return h.next.AfterMFAEnabled(ctx, user)
}

func (h *auditHook) AfterMFADisabled(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventMFADisabled, nil)
	return h.next.AfterMFADisabled(ctx, user)
}

func (h *auditHook) AfterLoginFailed(ctx context.Context, user *models.User, reason string) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventLoginFailed, models.JSONMap{"reason": reason})
	return h.next.AfterLoginFailed(ctx, user, reason)
}

func (h *auditHook) AfterAccountLocked(ctx context.Context, user *models.User) error {
	h.auth.recordAuditEvent(ctx, user.ID, models.AuditEventAccountLocked, nil)
	return h.next.AfterAccountLocked(ctx, user)
}
