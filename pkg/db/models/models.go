// Package models defines the database models for ezauth.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// JSONMap is a helper type for JSONB/JSON columns
type JSONMap map[string]any

// Value implements the driver.Valuer interface
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return "{}", nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface
func (j *JSONMap) Scan(value any) error {
	if value == nil {
		*j = make(JSONMap)
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("type assertion to []byte or string failed")
	}

	return json.Unmarshal(bytes, j)
}

// User represents a user in the system.
type User struct {
	ID                  string     `db:"id" json:"id"`
	Email               string     `db:"email" json:"email"`
	Username            string     `db:"username" json:"username"`
	PasswordHash        string     `db:"password_hash" json:"-"`
	Provider            string     `db:"provider" json:"provider"`
	ProviderID          *string    `db:"provider_id" json:"provider_id,omitempty"`
	EmailVerified       bool       `db:"email_verified" json:"email_verified"`
	AppMetadata         JSONMap    `db:"app_metadata" json:"app_metadata"`
	UserMetadata        JSONMap    `db:"user_metadata" json:"user_metadata"`
	FirstName           string     `db:"first_name" json:"first_name"`
	LastName            string     `db:"last_name" json:"last_name"`
	LastActiveAt        *time.Time `db:"last_active_at" json:"last_active_at,omitempty"`
	LastLoginAt         *time.Time `db:"last_login_at" json:"last_login_at,omitempty"`
	Locale              string     `db:"locale" json:"locale"`
	Timezone            string     `db:"timezone" json:"timezone"`
	EmailVerifiedAt     *time.Time `db:"email_verified_at" json:"email_verified_at,omitempty"`
	Phone               string     `db:"phone" json:"phone"`
	PhoneVerified       bool       `db:"phone_verified" json:"phone_verified"`
	IsActive            bool       `db:"is_active" json:"is_active"`
	AvatarURL           string     `db:"avatar_url" json:"avatar_url"`
	Nickname            string     `db:"nickname" json:"nickname"`
	Roles               string     `db:"roles" json:"roles"`
	MfaSecret           *string    `db:"mfa_secret" json:"-"`
	MfaEnabled          bool       `db:"mfa_enabled" json:"mfa_enabled"`
	FailedLoginAttempts int        `db:"failed_login_attempts" json:"-"`
	LockedUntil         *time.Time `db:"locked_until" json:"-"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `db:"updated_at" json:"updated_at"`
}

// HasRole checks if the user has the specified role.
// Roles are stored as a comma-separated string.
func (u *User) HasRole(role string) bool {
	for _, r := range u.GetRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the user has any of the given roles.
func (u *User) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the user has all of the given roles.
func (u *User) HasAllRoles(roles ...string) bool {
	for _, role := range roles {
		if !u.HasRole(role) {
			return false
		}
	}
	return true
}

// GetRoles returns the user's roles as a slice.
func (u *User) GetRoles() []string {
	if u.Roles == "" {
		return nil
	}
	parts := strings.Split(u.Roles, ",")
	roles := make([]string, 0, len(parts))
	for _, r := range parts {
		trimmed := strings.TrimSpace(r)
		if trimmed != "" {
			roles = append(roles, trimmed)
		}
	}
	return roles
}

// AddRole appends a role to the user's role list, avoiding duplicates.
func (u *User) AddRole(role string) {
	if u.HasRole(role) {
		return
	}
	if u.Roles == "" {
		u.Roles = role
	} else {
		u.Roles = u.Roles + "," + role
	}
}

// RemoveRole removes a role from the user's role list if present.
func (u *User) RemoveRole(role string) {
	roles := u.GetRoles()
	filtered := make([]string, 0, len(roles))
	for _, r := range roles {
		if r != role {
			filtered = append(filtered, r)
		}
	}
	u.Roles = strings.Join(filtered, ",")
}

// FullName returns the user's first and last name combined.
func (u *User) FullName() string {
	switch {
	case u.FirstName != "" && u.LastName != "":
		return u.FirstName + " " + u.LastName
	case u.FirstName != "":
		return u.FirstName
	case u.LastName != "":
		return u.LastName
	default:
		return ""
	}
}

// DisplayName returns the best available display name for the user.
// It prefers FullName over Username over the local part of the email.
func (u *User) DisplayName() string {
	if fn := u.FullName(); fn != "" {
		return fn
	}
	if u.Username != "" {
		return u.Username
	}
	if idx := strings.Index(u.Email, "@"); idx > 0 {
		return u.Email[:idx]
	}
	return u.Email
}

// IsOAuth returns true if the user signed up via an OAuth2 provider.
func (u *User) IsOAuth() bool {
	return u.Provider != "" && u.Provider != "local"
}

// IsLocal returns true if the user signed up with email/password.
func (u *User) IsLocal() bool {
	return u.Provider == "" || u.Provider == "local"
}

// Sanitize clears sensitive fields (e.g., PasswordHash) before serialization.
func (u *User) Sanitize() {
	u.PasswordHash = ""
}

// GetMeta retrieves a value from UserMetadata with type casting.
// It returns the value and a boolean indicating if the key exists and the type assertion was successful.
func GetMeta[T any](u *User, key string) (T, bool) {
	var zero T
	if u.UserMetadata == nil {
		return zero, false
	}
	val, ok := u.UserMetadata[key]
	if !ok {
		return zero, false
	}
	tVal, ok := val.(T)
	return tVal, ok
}

// SetMeta sets a value in UserMetadata.
// It initializes the map if it's nil.
func (u *User) SetMeta(key string, value any) {
	if u.UserMetadata == nil {
		u.UserMetadata = make(JSONMap)
	}
	u.UserMetadata[key] = value
}

// GetAppMeta retrieves a value from AppMetadata with type casting.
// It returns the value and a boolean indicating if the key exists and the type assertion was successful.
func GetAppMeta[T any](u *User, key string) (T, bool) {
	var zero T
	if u.AppMetadata == nil {
		return zero, false
	}
	val, ok := u.AppMetadata[key]
	if !ok {
		return zero, false
	}
	tVal, ok := val.(T)
	return tVal, ok
}

// SetAppMeta sets a value in AppMetadata.
// It initializes the map if it's nil.
func (u *User) SetAppMeta(key string, value any) {
	if u.AppMetadata == nil {
		u.AppMetadata = make(JSONMap)
	}
	u.AppMetadata[key] = value
}

const (
	TokenTypeAccess        = "access"
	TokenTypeRefresh       = "refresh"
	TokenTypePasswordless  = "passwordless"
	TokenTypePasswordReset = "password_reset"
	TokenTypeApiKey        = "apikey"
	TokenTypeMFAPreAuth    = "mfa_preauth"
	TokenTypeMFARecovery   = "mfa_recovery"
	TokenTypeSMSOTP        = "sms_otp"
	TokenTypeTrustedDevice = "trusted_device"
	TokenTypeInvitation    = "invitation"
)

// WebAuthn ceremony challenge types, stored on WebauthnChallenge.ChallengeType.
const (
	WebauthnChallengeTypeRegistration = "webauthn_registration"
	WebauthnChallengeTypeLogin        = "webauthn_login"
)

// WebauthnChallenge stores the server-side state (challenge and ceremony
// parameters) of an in-progress WebAuthn registration or login ceremony,
// looked up by an opaque SessionKey. Unlike Token, UserID may be empty: a
// discoverable (usernameless) login challenge has no known user until the
// assertion is verified.
type WebauthnChallenge struct {
	ID            string    `db:"id" json:"-"`
	SessionKey    string    `db:"session_key" json:"-"`
	ChallengeType string    `db:"challenge_type" json:"-"`
	UserID        string    `db:"user_id" json:"-"`
	Data          JSONMap   `db:"data" json:"-"`
	ExpiresAt     time.Time `db:"expires_at" json:"-"`
	CreatedAt     time.Time `db:"created_at" json:"-"`
}

// WebauthnCredential represents a registered WebAuthn/passkey credential for a user.
type WebauthnCredential struct {
	ID              string     `db:"id" json:"id"`
	UserID          string     `db:"user_id" json:"user_id"`
	CredentialID    string     `db:"credential_id" json:"-"`
	PublicKey       string     `db:"public_key" json:"-"`
	SignCount       uint32     `db:"sign_count" json:"sign_count"`
	Transports      string     `db:"transports" json:"transports"`
	AttestationType string     `db:"attestation_type" json:"attestation_type"`
	Name            string     `db:"name" json:"name"`
	Data            JSONMap    `db:"data" json:"-"`
	CreatedAt       time.Time  `db:"created_at" json:"created_at"`
	LastUsedAt      *time.Time `db:"last_used_at" json:"last_used_at,omitempty"`
}

// Token represents an authentication or action token (e.g., refresh token, password reset token).
type Token struct {
	ID        string    `db:"id" json:"id"`
	UserID    string    `db:"user_id" json:"user_id"`
	Token     string    `db:"token" json:"token"`
	TokenType string    `db:"token_type" json:"token_type"` // access, refresh, passwordless
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	Revoked   bool      `db:"revoked" json:"revoked"`
	Metadata  JSONMap   `db:"metadata" json:"metadata"`
}
