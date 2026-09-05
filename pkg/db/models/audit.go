package models

import "time"

// Audit log event types, stored on AuditLog.EventType. Fired by the
// built-in audit hook (see service.Hook) for the lifecycle events ezauth
// already observes, plus RBAC role grant/revoke (see
// service.UserRoleGrant/UserRoleRevoke); "email verification" isn't
// included since ezauth doesn't yet have an email-verification-confirm flow.
const (
	AuditEventUserCreated            = "user.created"
	AuditEventUserDeleted            = "user.deleted"
	AuditEventLoginSucceeded         = "login.succeeded"
	AuditEventLoginFailed            = "login.failed"
	AuditEventLogoutSucceeded        = "logout.succeeded"
	AuditEventPasswordResetRequested = "password_reset.requested"
	AuditEventPasswordResetConfirmed = "password_reset.confirmed"
	AuditEventOAuth2SignedIn         = "oauth2.signed_in"
	AuditEventOAuth2Created          = "oauth2.created"
	AuditEventImpersonationStarted   = "impersonation.started"
	AuditEventImpersonationEnded     = "impersonation.ended"
	AuditEventMFAEnabled             = "mfa.enabled"
	AuditEventMFADisabled            = "mfa.disabled"
	AuditEventAccountLocked          = "account.locked"
	AuditEventRoleGranted            = "role.granted"
	AuditEventRoleRevoked            = "role.revoked"
)

// AuditLog represents one persisted security-relevant event for a user
// (see the AuditEvent* constants).
type AuditLog struct {
	ID        string    `db:"id" json:"id"`
	UserID    string    `db:"user_id" json:"user_id"`
	EventType string    `db:"event_type" json:"event_type"`
	Metadata  JSONMap   `db:"metadata" json:"metadata,omitempty"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// AuditLogFilter defines the search/filter criteria for listing a user's
// audit log. All fields are optional (zero-valued means "no filter").
type AuditLogFilter struct {
	// EventType filters to a single AuditEvent* value; "" means no filter.
	EventType string

	// Since/Until filter by CreatedAt (inclusive).
	Since *time.Time
	Until *time.Time
}
