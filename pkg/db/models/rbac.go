package models

import "time"

// Role represents a named RBAC role, granted to users via ezauth_user_roles
// and holding permissions via ezauth_role_permissions.
type Role struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// Permission represents a named RBAC permission, granted to roles via
// ezauth_role_permissions.
type Permission struct {
	ID          string    `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}
