// Package repository provides the data access layer for ezauth.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/db/repository/mysql"
	"github.com/josuebrunel/ezauth/pkg/db/repository/postgres"
	"github.com/josuebrunel/ezauth/pkg/db/repository/sqlite"
	"github.com/josuebrunel/gopkg/xlog"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/scan"
)

const (
	DialectPSQL   = "postgres"
	DialectSqlite = "sqlite"
	DialectMysql  = "mysql"
)

type UserQuerier interface {
	QueryUserInsert(ctx context.Context, user *models.User) bob.Query
	QueryUserGetByEmail(ctx context.Context, email string) bob.Query
	QueryUserGetByUsername(ctx context.Context, username string) bob.Query
	QueryUserGetByPhone(ctx context.Context, phone string) bob.Query
	QueryUserGetByID(ctx context.Context, id string) bob.Query
	QueryUserGetByProvider(ctx context.Context, provider, providerID string) bob.Query
	QueryUserUpdate(ctx context.Context, user *models.User) bob.Query
	QueryUserSetLockoutState(ctx context.Context, userID string, attempts int, lockedUntil *time.Time, isActive bool) bob.Query
	QueryUserDelete(ctx context.Context, id string) bob.Query
	QueryUsersList(ctx context.Context, filter models.UserListFilter, limit, offset int) bob.Query
}

type TokenQuerier interface {
	QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query
	QueryTokenGetByID(ctx context.Context, id string) bob.Query
	QueryTokenGetByToken(ctx context.Context, token string) bob.Query
	QueryTokenListByUserIDAndType(ctx context.Context, userID, tokenType string) bob.Query
	QueryTokenListByUserID(ctx context.Context, userID string, limit int) bob.Query
	QueryTokenRevoke(ctx context.Context, id string) bob.Query
	QueryTokenRevokeAllByUserID(ctx context.Context, userID string) bob.Query
	QueryTokenRevokeFamily(ctx context.Context, userID, familyID string) bob.Query
	QueryTokenDelete(ctx context.Context, id string) bob.Query
}

type WebauthnCredentialQuerier interface {
	QueryWebauthnCredentialInsert(ctx context.Context, cred *models.WebauthnCredential) bob.Query
	QueryWebauthnCredentialGetByID(ctx context.Context, id string) bob.Query
	QueryWebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) bob.Query
	QueryWebauthnCredentialListByUserID(ctx context.Context, userID string) bob.Query
	QueryWebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) bob.Query
	QueryWebauthnCredentialDelete(ctx context.Context, id string) bob.Query
}

type WebauthnChallengeQuerier interface {
	QueryWebauthnChallengeInsert(ctx context.Context, ch *models.WebauthnChallenge) bob.Query
	QueryWebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) bob.Query
	QueryWebauthnChallengeDelete(ctx context.Context, id string) bob.Query
}

type AuditLogQuerier interface {
	QueryAuditLogInsert(ctx context.Context, log *models.AuditLog) bob.Query
	QueryAuditLogListByUserID(ctx context.Context, userID string, filter models.AuditLogFilter, limit, offset int) bob.Query
}

type RoleQuerier interface {
	QueryRoleInsert(ctx context.Context, role *models.Role) bob.Query
	QueryRoleGetByID(ctx context.Context, id string) bob.Query
	QueryRoleGetByName(ctx context.Context, name string) bob.Query
	QueryRolesList(ctx context.Context) bob.Query
	QueryRoleDelete(ctx context.Context, id string) bob.Query
}

type PermissionQuerier interface {
	QueryPermissionInsert(ctx context.Context, permission *models.Permission) bob.Query
	QueryPermissionGetByID(ctx context.Context, id string) bob.Query
	QueryPermissionGetByName(ctx context.Context, name string) bob.Query
	QueryPermissionsList(ctx context.Context) bob.Query
	QueryPermissionDelete(ctx context.Context, id string) bob.Query
}

// RBACAssignmentQuerier covers the ezauth_user_roles/ezauth_role_permissions
// join tables: granting/revoking assignments, and the joined reads that
// resolve a user's effective roles/permissions.
type RBACAssignmentQuerier interface {
	QueryUserRoleInsert(ctx context.Context, userID, roleID string) bob.Query
	QueryUserRoleDelete(ctx context.Context, userID, roleID string) bob.Query
	QueryRolesByUserID(ctx context.Context, userID string) bob.Query
	QueryRolePermissionInsert(ctx context.Context, roleID, permissionID string) bob.Query
	QueryRolePermissionDelete(ctx context.Context, roleID, permissionID string) bob.Query
	QueryPermissionsByRoleID(ctx context.Context, roleID string) bob.Query
	QueryPermissionsByUserID(ctx context.Context, userID string) bob.Query
}

type OrganizationQuerier interface {
	QueryOrganizationInsert(ctx context.Context, org *models.Organization) bob.Query
	QueryOrganizationGetByID(ctx context.Context, id string) bob.Query
	QueryOrganizationsList(ctx context.Context) bob.Query
	QueryOrganizationDelete(ctx context.Context, id string) bob.Query
}

// OrgMemberQuerier covers the ezauth_org_members join table: upserting/
// removing a (user, org) membership, and the joined reads that resolve a
// user's orgs or an org's members (with role name).
type OrgMemberQuerier interface {
	QueryOrgMemberUpsert(ctx context.Context, orgID, userID, roleID string) bob.Query
	QueryOrgMemberRemove(ctx context.Context, orgID, userID string) bob.Query
	QueryOrgMembersByOrgID(ctx context.Context, orgID string) bob.Query
	QueryOrganizationsByUserID(ctx context.Context, userID string) bob.Query
}

type Querier interface {
	UserQuerier
	TokenQuerier
	WebauthnCredentialQuerier
	WebauthnChallengeQuerier
	AuditLogQuerier
	RoleQuerier
	PermissionQuerier
	RBACAssignmentQuerier
	OrganizationQuerier
	OrgMemberQuerier
}

// Opts defines the options for opening a repository connection.
type Opts struct {
	Dialect string
	DSN     string
	Schema  string
}

// Repository handles all database operations.
type Repository struct {
	Opts Opts
	bdb  bob.DB
	db   *sql.DB
	Querier
}

// New creates a new Repository with the given database connection and dialect.
func New(db *sql.DB, dialect string) *Repository {
	querier := getDialectQuery(dialect)
	bdb := bob.NewDB(db)

	return &Repository{
		db:      db,
		bdb:     bdb,
		Querier: querier,
		Opts:    Opts{Dialect: dialect},
	}
}

// Open opens a new database connection and returns a Repository.
func Open(opts Opts) (*Repository, error) {
	db, err := getDBConnection(opts)
	if err != nil {
		return nil, err
	}
	return New(db, opts.Dialect), nil
}

// DB returns the underlying sql.DB connection.
func (r Repository) DB() *sql.DB {
	return r.db
}

// Ping pings the database to check if the connection is alive.
func (r *Repository) Ping() error {
	return r.bdb.Ping()
}

// Close closes the database connection.
func (r *Repository) Close() error {
	return r.bdb.Close()
}

// UserCreate creates a new user in the database.
func (r Repository) UserCreate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserInsert(ctx, user)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create user", "error", err, "email", user.Email)
			return nil, err
		}
		return r.UserGetByID(ctx, user.ID)
	}

	createdUser, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to create user", "error", err, "email", user.Email)
		return nil, err
	}
	return createdUser, nil
}

// UserGetByProvider retrieves a user by their OAuth2 provider and provider ID.
func (r Repository) UserGetByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	query := r.QueryUserGetByProvider(ctx, provider, providerID)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by provider", "error", err, "provider", provider, "provider_id", providerID)
		return nil, err
	}
	return user, nil
}

// UserGetByEmail retrieves a user by their email address.
func (r Repository) UserGetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := r.QueryUserGetByEmail(ctx, email)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by email", "error", err, "email", email)
		return nil, err
	}
	return user, nil
}

// UserGetByUsername retrieves a user by their username.
func (r Repository) UserGetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := r.QueryUserGetByUsername(ctx, username)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by username", "error", err, "username", username)
		return nil, err
	}
	return user, nil
}

// UserGetByPhone retrieves a user by their phone number.
func (r Repository) UserGetByPhone(ctx context.Context, phone string) (*models.User, error) {
	query := r.QueryUserGetByPhone(ctx, phone)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by phone", "error", err)
		return nil, err
	}
	return user, nil
}

// UserGetByID retrieves a user by their ID.
func (r Repository) UserGetByID(ctx context.Context, id string) (*models.User, error) {
	query := r.QueryUserGetByID(ctx, id)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by id", "error", err, "id", id)
		return nil, err
	}
	return user, nil
}

// UserUpdate updates an existing user in the database.
func (r Repository) UserUpdate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserUpdate(ctx, user)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to update user", "error", err, "email", user.Email)
			return nil, err
		}
		return r.UserGetByID(ctx, user.ID)
	}

	updatedUser, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to update user", "error", err, "email", user.Email)
		return nil, err
	}
	return updatedUser, nil
}

// UserSetLockoutState sets a user's brute-force lockout bookkeeping (failed
// attempt counter, lockout expiry, and the enforced is_active gate) in a single
// targeted update, independent of UserUpdate's partial-update semantics — which
// can't clear lockedUntil back to NULL once set.
func (r Repository) UserSetLockoutState(ctx context.Context, userID string, attempts int, lockedUntil *time.Time, isActive bool) (*models.User, error) {
	query := r.QueryUserSetLockoutState(ctx, userID, attempts, lockedUntil, isActive)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to set user lockout state", "error", err, "user_id", userID)
			return nil, err
		}
		return r.UserGetByID(ctx, userID)
	}

	updatedUser, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to set user lockout state", "error", err, "user_id", userID)
		return nil, err
	}
	return updatedUser, nil
}

// UserDelete deletes a user from the database.
func (r Repository) UserDelete(ctx context.Context, id string) error {
	query := r.QueryUserDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete user", "error", err, "id", id)
		return err
	}
	return nil
}

// UsersList lists/filters users (see models.UserListFilter), most recently
// created first. hasMore reports whether more results exist beyond this
// page, computed by fetching one extra row rather than a separate COUNT(*) query.
func (r Repository) UsersList(ctx context.Context, filter models.UserListFilter, limit, offset int) (users []*models.User, hasMore bool, err error) {
	query := r.QueryUsersList(ctx, filter, limit+1, offset)
	users, err = bob.All(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to list users", "error", err)
		return nil, false, err
	}
	if len(users) > limit {
		return users[:limit], true, nil
	}
	return users, false, nil
}

// TokenCreate creates a new refresh token or password reset token in the database.
func (r Repository) TokenCreate(ctx context.Context, token *models.Token) (*models.Token, error) {
	query := r.QueryTokenInsert(ctx, token)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create token", "error", err)
			return nil, err
		}
		// Since we generate ID in Go, we can use it to fetch
		return r.TokenGetByID(ctx, token.ID)
	}

	createdToken, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to create token", "error", err)
		return nil, err
	}
	return createdToken, nil
}

// TokenGetByID retrieves a token by its ID.
func (r Repository) TokenGetByID(ctx context.Context, id string) (*models.Token, error) {
	query := r.QueryTokenGetByID(ctx, id)
	token, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to get token by id", "error", err, "id", id)
		return nil, err
	}
	return token, nil
}

// TokenGetByToken retrieves a token by its token value.
func (r Repository) TokenGetByToken(ctx context.Context, tokenValue string) (*models.Token, error) {
	query := r.QueryTokenGetByToken(ctx, tokenValue)
	token, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to get token by token", "error", err)
		return nil, err
	}
	return token, nil
}

// TokenListByUserIDAndType lists all non-revoked tokens of a given type for a user
// (e.g. trusted devices).
func (r Repository) TokenListByUserIDAndType(ctx context.Context, userID, tokenType string) ([]*models.Token, error) {
	query := r.QueryTokenListByUserIDAndType(ctx, userID, tokenType)
	tokens, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to list tokens by user and type", "error", err, "user_id", userID, "token_type", tokenType)
		return nil, err
	}
	return tokens, nil
}

// TokenListByUserID lists the most recent tokens of any type for a user
// (e.g. for an admin-facing auth history view), most recently created first.
func (r Repository) TokenListByUserID(ctx context.Context, userID string, limit int) ([]*models.Token, error) {
	query := r.QueryTokenListByUserID(ctx, userID, limit)
	tokens, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to list tokens by user", "error", err, "user_id", userID)
		return nil, err
	}
	return tokens, nil
}

// TokenRevoke marks a token as revoked in the database.
func (r Repository) TokenRevoke(ctx context.Context, id string) error {
	query := r.QueryTokenRevoke(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke token", "error", err, "id", id)
		return err
	}
	return nil
}

// TokenRevokeAllByUserID revokes all non-revoked tokens for a given user.
func (r Repository) TokenRevokeAllByUserID(ctx context.Context, userID string) error {
	query := r.QueryTokenRevokeAllByUserID(ctx, userID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke all tokens for user", "error", err, "user_id", userID)
		return err
	}
	return nil
}

// TokenRevokeFamily revokes every active refresh token in a rotation
// family (see the family_id tagged in Token.Metadata by tokenCreateForActor)
// in a single bulk UPDATE, in response to a detected reuse of an
// already-rotated-out token.
func (r Repository) TokenRevokeFamily(ctx context.Context, userID, familyID string) error {
	query := r.QueryTokenRevokeFamily(ctx, userID, familyID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke token family", "error", err, "user_id", userID, "family_id", familyID)
		return err
	}
	return nil
}

// TokenDelete deletes a token from the database.
func (r Repository) TokenDelete(ctx context.Context, id string) error {
	query := r.QueryTokenDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete token", "error", err, "id", id)
		return err
	}
	return nil
}

// WebauthnCredentialCreate creates a new WebAuthn credential record.
func (r Repository) WebauthnCredentialCreate(ctx context.Context, cred *models.WebauthnCredential) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialInsert(ctx, cred)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create webauthn credential", "error", err, "user_id", cred.UserID)
			return nil, err
		}
		return r.WebauthnCredentialGetByID(ctx, cred.ID)
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to create webauthn credential", "error", err, "user_id", cred.UserID)
		return nil, err
	}
	return created, nil
}

// WebauthnCredentialGetByID retrieves a WebAuthn credential by its record ID.
func (r Repository) WebauthnCredentialGetByID(ctx context.Context, id string) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialGetByID(ctx, id)
	cred, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to get webauthn credential by id", "error", err, "id", id)
		return nil, err
	}
	return cred, nil
}

// WebauthnCredentialGetByCredentialID retrieves a WebAuthn credential by its (base64url-encoded) credential ID.
func (r Repository) WebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialGetByCredentialID(ctx, credentialID)
	cred, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to get webauthn credential by credential id", "error", err)
		return nil, err
	}
	return cred, nil
}

// WebauthnCredentialListByUserID lists all WebAuthn credentials belonging to a user.
func (r Repository) WebauthnCredentialListByUserID(ctx context.Context, userID string) ([]*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialListByUserID(ctx, userID)
	creds, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to list webauthn credentials", "error", err, "user_id", userID)
		return nil, err
	}
	return creds, nil
}

// WebauthnCredentialUpdate updates a WebAuthn credential (e.g. sign count after a login).
func (r Repository) WebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialUpdate(ctx, cred)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to update webauthn credential", "error", err, "id", cred.ID)
			return nil, err
		}
		return r.WebauthnCredentialGetByID(ctx, cred.ID)
	}

	updated, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to update webauthn credential", "error", err, "id", cred.ID)
		return nil, err
	}
	return updated, nil
}

// WebauthnCredentialDelete deletes a WebAuthn credential.
func (r Repository) WebauthnCredentialDelete(ctx context.Context, id string) error {
	query := r.QueryWebauthnCredentialDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete webauthn credential", "error", err, "id", id)
		return err
	}
	return nil
}

// WebauthnChallengeCreate persists a WebAuthn ceremony's SessionData.
func (r Repository) WebauthnChallengeCreate(ctx context.Context, ch *models.WebauthnChallenge) (*models.WebauthnChallenge, error) {
	query := r.QueryWebauthnChallengeInsert(ctx, ch)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create webauthn challenge", "error", err)
			return nil, err
		}
		return r.WebauthnChallengeGetBySessionKey(ctx, ch.SessionKey)
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnChallenge]())
	if err != nil {
		xlog.Error("Failed to create webauthn challenge", "error", err)
		return nil, err
	}
	return created, nil
}

// WebauthnChallengeGetBySessionKey retrieves a WebAuthn ceremony challenge by its opaque session key.
func (r Repository) WebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) (*models.WebauthnChallenge, error) {
	query := r.QueryWebauthnChallengeGetBySessionKey(ctx, sessionKey)
	ch, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnChallenge]())
	if err != nil {
		xlog.Error("Failed to get webauthn challenge by session key", "error", err)
		return nil, err
	}
	return ch, nil
}

// WebauthnChallengeDelete deletes a WebAuthn ceremony challenge, e.g. after it has been consumed.
func (r Repository) WebauthnChallengeDelete(ctx context.Context, id string) error {
	query := r.QueryWebauthnChallengeDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete webauthn challenge", "error", err, "id", id)
		return err
	}
	return nil
}

// AuditLogCreate persists a security-relevant audit event.
func (r Repository) AuditLogCreate(ctx context.Context, log *models.AuditLog) (*models.AuditLog, error) {
	query := r.QueryAuditLogInsert(ctx, log)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create audit log", "error", err, "user_id", log.UserID, "event_type", log.EventType)
			return nil, err
		}
		return log, nil
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.AuditLog]())
	if err != nil {
		xlog.Error("Failed to create audit log", "error", err, "user_id", log.UserID, "event_type", log.EventType)
		return nil, err
	}
	return created, nil
}

// AuditLogListByUserID lists/filters a user's audit log (see
// models.AuditLogFilter), most recent first. hasMore reports whether more
// results exist beyond this page, computed by fetching one extra row rather
// than a separate COUNT(*) query.
func (r Repository) AuditLogListByUserID(ctx context.Context, userID string, filter models.AuditLogFilter, limit, offset int) (logs []*models.AuditLog, hasMore bool, err error) {
	query := r.QueryAuditLogListByUserID(ctx, userID, filter, limit+1, offset)
	logs, err = bob.All(ctx, r.bdb, query, scan.StructMapper[*models.AuditLog]())
	if err != nil {
		xlog.Error("Failed to list audit logs", "error", err, "user_id", userID)
		return nil, false, err
	}
	if len(logs) > limit {
		return logs[:limit], true, nil
	}
	return logs, false, nil
}

// RoleCreate creates a new RBAC role.
func (r Repository) RoleCreate(ctx context.Context, role *models.Role) (*models.Role, error) {
	query := r.QueryRoleInsert(ctx, role)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create role", "error", err, "name", role.Name)
			return nil, err
		}
		return r.RoleGetByID(ctx, role.ID)
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Role]())
	if err != nil {
		xlog.Error("Failed to create role", "error", err, "name", role.Name)
		return nil, err
	}
	return created, nil
}

// RoleGetByID retrieves a role by its ID.
func (r Repository) RoleGetByID(ctx context.Context, id string) (*models.Role, error) {
	query := r.QueryRoleGetByID(ctx, id)
	role, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Role]())
	if err != nil {
		xlog.Error("Failed to get role by id", "error", err, "id", id)
		return nil, err
	}
	return role, nil
}

// RoleGetByName retrieves a role by its unique name.
func (r Repository) RoleGetByName(ctx context.Context, name string) (*models.Role, error) {
	query := r.QueryRoleGetByName(ctx, name)
	role, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Role]())
	if err != nil {
		xlog.Error("Failed to get role by name", "error", err, "name", name)
		return nil, err
	}
	return role, nil
}

// RolesList lists all RBAC roles.
func (r Repository) RolesList(ctx context.Context) ([]*models.Role, error) {
	query := r.QueryRolesList(ctx)
	roles, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Role]())
	if err != nil {
		xlog.Error("Failed to list roles", "error", err)
		return nil, err
	}
	return roles, nil
}

// RoleDelete deletes a role. Matching ezauth_user_roles/ezauth_role_permissions
// rows are removed via ON DELETE CASCADE.
func (r Repository) RoleDelete(ctx context.Context, id string) error {
	query := r.QueryRoleDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete role", "error", err, "id", id)
		return err
	}
	return nil
}

// PermissionCreate creates a new RBAC permission.
func (r Repository) PermissionCreate(ctx context.Context, permission *models.Permission) (*models.Permission, error) {
	query := r.QueryPermissionInsert(ctx, permission)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create permission", "error", err, "name", permission.Name)
			return nil, err
		}
		return r.PermissionGetByID(ctx, permission.ID)
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Permission]())
	if err != nil {
		xlog.Error("Failed to create permission", "error", err, "name", permission.Name)
		return nil, err
	}
	return created, nil
}

// PermissionGetByID retrieves a permission by its ID.
func (r Repository) PermissionGetByID(ctx context.Context, id string) (*models.Permission, error) {
	query := r.QueryPermissionGetByID(ctx, id)
	permission, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Permission]())
	if err != nil {
		xlog.Error("Failed to get permission by id", "error", err, "id", id)
		return nil, err
	}
	return permission, nil
}

// PermissionGetByName retrieves a permission by its unique name.
func (r Repository) PermissionGetByName(ctx context.Context, name string) (*models.Permission, error) {
	query := r.QueryPermissionGetByName(ctx, name)
	permission, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Permission]())
	if err != nil {
		xlog.Error("Failed to get permission by name", "error", err, "name", name)
		return nil, err
	}
	return permission, nil
}

// PermissionsList lists all RBAC permissions.
func (r Repository) PermissionsList(ctx context.Context) ([]*models.Permission, error) {
	query := r.QueryPermissionsList(ctx)
	permissions, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Permission]())
	if err != nil {
		xlog.Error("Failed to list permissions", "error", err)
		return nil, err
	}
	return permissions, nil
}

// PermissionDelete deletes a permission. Matching ezauth_role_permissions
// rows are removed via ON DELETE CASCADE.
func (r Repository) PermissionDelete(ctx context.Context, id string) error {
	query := r.QueryPermissionDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete permission", "error", err, "id", id)
		return err
	}
	return nil
}

// UserRoleGrant grants a role to a user (inserts into ezauth_user_roles).
func (r Repository) UserRoleGrant(ctx context.Context, userID, roleID string) error {
	query := r.QueryUserRoleInsert(ctx, userID, roleID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to grant role to user", "error", err, "user_id", userID, "role_id", roleID)
		return err
	}
	return nil
}

// UserRoleRevoke revokes a role from a user (deletes from ezauth_user_roles).
func (r Repository) UserRoleRevoke(ctx context.Context, userID, roleID string) error {
	query := r.QueryUserRoleDelete(ctx, userID, roleID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke role from user", "error", err, "user_id", userID, "role_id", roleID)
		return err
	}
	return nil
}

// RolesByUserID lists the roles granted to a user.
func (r Repository) RolesByUserID(ctx context.Context, userID string) ([]*models.Role, error) {
	query := r.QueryRolesByUserID(ctx, userID)
	roles, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Role]())
	if err != nil {
		xlog.Error("Failed to list roles by user", "error", err, "user_id", userID)
		return nil, err
	}
	return roles, nil
}

// RolePermissionGrant grants a permission to a role (inserts into ezauth_role_permissions).
func (r Repository) RolePermissionGrant(ctx context.Context, roleID, permissionID string) error {
	query := r.QueryRolePermissionInsert(ctx, roleID, permissionID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to grant permission to role", "error", err, "role_id", roleID, "permission_id", permissionID)
		return err
	}
	return nil
}

// RolePermissionRevoke revokes a permission from a role (deletes from ezauth_role_permissions).
func (r Repository) RolePermissionRevoke(ctx context.Context, roleID, permissionID string) error {
	query := r.QueryRolePermissionDelete(ctx, roleID, permissionID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke permission from role", "error", err, "role_id", roleID, "permission_id", permissionID)
		return err
	}
	return nil
}

// PermissionsByRoleID lists the permissions granted to a role.
func (r Repository) PermissionsByRoleID(ctx context.Context, roleID string) ([]*models.Permission, error) {
	query := r.QueryPermissionsByRoleID(ctx, roleID)
	permissions, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Permission]())
	if err != nil {
		xlog.Error("Failed to list permissions by role", "error", err, "role_id", roleID)
		return nil, err
	}
	return permissions, nil
}

// PermissionsByUserID lists the permissions a user holds, resolved transitively
// through every role granted to them (ezauth_user_roles -> ezauth_role_permissions
// -> ezauth_permissions).
func (r Repository) PermissionsByUserID(ctx context.Context, userID string) ([]*models.Permission, error) {
	query := r.QueryPermissionsByUserID(ctx, userID)
	permissions, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Permission]())
	if err != nil {
		xlog.Error("Failed to list permissions by user", "error", err, "user_id", userID)
		return nil, err
	}
	return permissions, nil
}

// OrganizationCreate creates a new organization.
func (r Repository) OrganizationCreate(ctx context.Context, org *models.Organization) (*models.Organization, error) {
	query := r.QueryOrganizationInsert(ctx, org)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create organization", "error", err, "name", org.Name)
			return nil, err
		}
		return r.OrganizationGetByID(ctx, org.ID)
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Organization]())
	if err != nil {
		xlog.Error("Failed to create organization", "error", err, "name", org.Name)
		return nil, err
	}
	return created, nil
}

// OrganizationGetByID retrieves an organization by its ID.
func (r Repository) OrganizationGetByID(ctx context.Context, id string) (*models.Organization, error) {
	query := r.QueryOrganizationGetByID(ctx, id)
	org, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Organization]())
	if err != nil {
		xlog.Error("Failed to get organization by id", "error", err, "id", id)
		return nil, err
	}
	return org, nil
}

// OrganizationsList lists all organizations.
func (r Repository) OrganizationsList(ctx context.Context) ([]*models.Organization, error) {
	query := r.QueryOrganizationsList(ctx)
	orgs, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Organization]())
	if err != nil {
		xlog.Error("Failed to list organizations", "error", err)
		return nil, err
	}
	return orgs, nil
}

// OrganizationDelete deletes an organization. Matching ezauth_org_members
// rows are removed via ON DELETE CASCADE.
func (r Repository) OrganizationDelete(ctx context.Context, id string) error {
	query := r.QueryOrganizationDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete organization", "error", err, "id", id)
		return err
	}
	return nil
}

// OrgMemberUpsert grants a user a role within an organization, or updates
// their role if the (org, user) membership already exists.
func (r Repository) OrgMemberUpsert(ctx context.Context, orgID, userID, roleID string) error {
	query := r.QueryOrgMemberUpsert(ctx, orgID, userID, roleID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to upsert org member", "error", err, "org_id", orgID, "user_id", userID, "role_id", roleID)
		return err
	}
	return nil
}

// OrgMemberRemove removes a user's membership from an organization.
func (r Repository) OrgMemberRemove(ctx context.Context, orgID, userID string) error {
	query := r.QueryOrgMemberRemove(ctx, orgID, userID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to remove org member", "error", err, "org_id", orgID, "user_id", userID)
		return err
	}
	return nil
}

// OrgMembersByOrgID lists an organization's members, with each member's role name joined in.
func (r Repository) OrgMembersByOrgID(ctx context.Context, orgID string) ([]*models.OrgMember, error) {
	query := r.QueryOrgMembersByOrgID(ctx, orgID)
	members, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.OrgMember]())
	if err != nil {
		xlog.Error("Failed to list org members", "error", err, "org_id", orgID)
		return nil, err
	}
	return members, nil
}

// OrganizationsByUserID lists the organizations a user belongs to.
func (r Repository) OrganizationsByUserID(ctx context.Context, userID string) ([]*models.Organization, error) {
	query := r.QueryOrganizationsByUserID(ctx, userID)
	orgs, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Organization]())
	if err != nil {
		xlog.Error("Failed to list organizations by user", "error", err, "user_id", userID)
		return nil, err
	}
	return orgs, nil
}

func getDialectQuery(dbDialect string) Querier {
	switch dbDialect {
	case "postgres":
		return &postgres.PSQLQuerier{}
	case "mysql":
		return &mysql.MysqlQuerier{}
	case "sqlite", "sqlite3":
		return &sqlite.SqliteQuerier{}
	default:
		return &sqlite.SqliteQuerier{}
	}
}

func getDBConnection(opts Opts) (*sql.DB, error) {
	var (
		db  *sql.DB
		err error
	)

	switch opts.Dialect {
	case DialectPSQL:
		db, err = postgres.GetDBConnection(opts.DSN)
		opts.Dialect = DialectPSQL
		if err == nil && opts.Schema != "" {
			for _, c := range opts.Schema {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
					return nil, fmt.Errorf("invalid schema name %q: only alphanumeric and underscore characters are allowed", opts.Schema)
				}
			}
			if _, err := db.Exec("CREATE SCHEMA IF NOT EXISTS " + opts.Schema); err != nil {
				xlog.Error("failed to create schema", "error", err, "schema", opts.Schema)
				return nil, err
			}
			if _, err := db.Exec("SET search_path TO " + opts.Schema); err != nil {
				xlog.Error("failed to set search_path", "error", err, "schema", opts.Schema)
				return nil, err
			}
		}
	case DialectMysql:
		db, err = mysql.GetDBConnection(opts.DSN)
		opts.Dialect = DialectMysql
	default:
		db, err = sqlite.GetDBConnection(opts.DSN)
		opts.Dialect = DialectSqlite
	}

	if err != nil {
		xlog.Error("failed to open connection", "error", err, "dsn", opts.DSN)
		return nil, err
	}

	if err := db.Ping(); err != nil {
		xlog.Error("failed to ping database", "error", err)
		return nil, err
	}

	return db, nil
}
