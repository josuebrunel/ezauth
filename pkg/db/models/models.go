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
	ID              string     `db:"id" json:"id"`
	Email           string     `db:"email" json:"email"`
	PasswordHash    string     `db:"password_hash" json:"-"`
	Provider        string     `db:"provider" json:"provider"`
	ProviderID      *string    `db:"provider_id" json:"provider_id,omitempty"`
	EmailVerified   bool       `db:"email_verified" json:"email_verified"`
	AppMetadata     JSONMap    `db:"app_metadata" json:"app_metadata"`
	UserMetadata    JSONMap    `db:"user_metadata" json:"user_metadata"`
	FirstName       string     `db:"first_name" json:"first_name"`
	LastName        string     `db:"last_name" json:"last_name"`
	LastActiveAt    *time.Time `db:"last_active_at" json:"last_active_at,omitempty"`
	Locale          string     `db:"locale" json:"locale"`
	Timezone        string     `db:"timezone" json:"timezone"`
	EmailVerifiedAt *time.Time `db:"email_verified_at" json:"email_verified_at,omitempty"`
	Roles           string     `db:"roles" json:"roles"`
	CreatedAt       time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at" json:"updated_at"`
}

// HasRole checks if the user has the specified role.
// Roles are stored as a comma-separated string.
func (u *User) HasRole(role string) bool {
	if u.Roles == "" {
		return false
	}
	roles := strings.Split(u.Roles, ",")
	for _, r := range roles {
		if strings.TrimSpace(r) == role {
			return true
		}
	}
	return false
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
)

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
