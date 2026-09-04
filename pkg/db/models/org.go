package models

import "time"

// Organization is a multi-tenant organization/team. Kept deliberately
// minimal (no settings/billing fields) — a consuming app that needs more
// can extend via its own table FK'd to this one.
type Organization struct {
	ID        string    `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// OrgMember represents one user's role within one organization
// (ezauth_org_members). RoleID is a foreign key into ezauth_roles — the
// same role catalog RequireRole/RequirePermission check against — so
// org-scoped membership draws from one role vocabulary, not a separate one.
// RoleName is populated by joined reads (e.g. OrgMembersByOrgID) for
// convenience.
type OrgMember struct {
	OrgID     string    `db:"org_id" json:"org_id"`
	UserID    string    `db:"user_id" json:"user_id"`
	RoleID    string    `db:"role_id" json:"role_id"`
	RoleName  string    `db:"role_name" json:"role_name,omitempty"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}
