# Repository Reference

The `repository.Repository` struct handles all database interactions. It supports multiple SQL dialects (SQLite, PostgreSQL, MySQL) via `bob`.

```go
type Repository struct {
    // ...
}
```

## Constructor

### `Open`

Opens a database connection and returns a Repository instance.

```go
func Open(opts Opts) (*Repository, error)
```

### `New`

Creates a Repository from an existing `sql.DB` connection.

```go
func New(db *sql.DB, dialect string) *Repository
```

## User Methods

### `UserCreate`
Inserts a new user record. automatically sets `CreatedAt` and `UpdatedAt` to the current UTC time if they are not provided.

```go
func (r Repository) UserCreate(ctx context.Context, user *models.User) (*models.User, error)
```

### `UserGetByEmail`
Retrieves a user by email.

```go
func (r Repository) UserGetByEmail(ctx context.Context, email string) (*models.User, error)
```

### `UserGetByID`
Retrieves a user by ID (UUID).

```go
func (r Repository) UserGetByID(ctx context.Context, id string) (*models.User, error)
```

### `UserGetByProvider`
Retrieves a user by OAuth2 provider ID.

```go
func (r Repository) UserGetByProvider(ctx context.Context, provider, providerID string) (*models.User, error)
```

### `UserGetByUsername`
Retrieves a user by username.

```go
func (r Repository) UserGetByUsername(ctx context.Context, username string) (*models.User, error)
```

### `UserGetByPhone`
Retrieves a user by phone number (used by SMS OTP login).

```go
func (r Repository) UserGetByPhone(ctx context.Context, phone string) (*models.User, error)
```

### `UserUpdate`
Updates an existing user record. Automatically updates `UpdatedAt` to the current UTC time.

```go
func (r Repository) UserUpdate(ctx context.Context, user *models.User) (*models.User, error)
```

### `UserSetLockoutState`
Sets the failed-attempt counter, an optional lockout expiry, and `IsActive` in one call. Used by both the account-lockout feature (temporary, auto-expiring) and admin suspend/reactivate (permanent, no expiry — `lockedUntil` is `nil`).

```go
func (r Repository) UserSetLockoutState(ctx context.Context, userID string, attempts int, lockedUntil *time.Time, isActive bool) (*models.User, error)
```

### `UserDelete`
Deletes a user record.

```go
func (r Repository) UserDelete(ctx context.Context, id string) error
```

### `UsersList`
Search/filter/paginate users via `models.UserListFilter` (`Search`, `Status`, `CreatedAfter`/`CreatedBefore`, `LastActiveAfter`/`LastActiveBefore`). `Search` is a case-insensitive substring match against email or username on all 3 dialects (Postgres uses `ILIKE`, sqlite/mysql `LIKE`).

```go
func (r Repository) UsersList(ctx context.Context, filter models.UserListFilter, limit, offset int) (users []*models.User, hasMore bool, err error)
```

## Token Methods

### `TokenCreate`
Stores a new refresh token or other temporary token (reset, magic link).

```go
func (r Repository) TokenCreate(ctx context.Context, token *models.Token) (*models.Token, error)
```

### `TokenGetByToken`
Retrieves a token record by its value.

```go
func (r Repository) TokenGetByToken(ctx context.Context, tokenValue string) (*models.Token, error)
```

### `TokenListByUserIDAndType`
Lists a user's tokens of a given type (e.g. all trusted-device tokens, or all invitation tokens issued by a user).

```go
func (r Repository) TokenListByUserIDAndType(ctx context.Context, userID, tokenType string) ([]*models.Token, error)
```

### `TokenListByUserID`
Lists a user's most recent tokens of any type, newest first. Backs `UserAuthHistory`.

```go
func (r Repository) TokenListByUserID(ctx context.Context, userID string, limit int) ([]*models.Token, error)
```

### `TokenRevoke`
Marks a token as revoked.

```go
func (r Repository) TokenRevoke(ctx context.Context, id string) error
```

### `TokenRevokeAllByUserID`
Revokes every active token for a user (e.g. all sessions, after a confirmed email change).

```go
func (r Repository) TokenRevokeAllByUserID(ctx context.Context, userID string) error
```

### `TokenDelete`
Permanently deletes a token.

```go
func (r Repository) TokenDelete(ctx context.Context, id string) error
```

## WebAuthn Credential Methods

Stores registered passkey/authenticator credentials for a user.

```go
func (r Repository) WebauthnCredentialCreate(ctx context.Context, cred *models.WebauthnCredential) (*models.WebauthnCredential, error)
func (r Repository) WebauthnCredentialGetByID(ctx context.Context, id string) (*models.WebauthnCredential, error)
func (r Repository) WebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) (*models.WebauthnCredential, error)
func (r Repository) WebauthnCredentialListByUserID(ctx context.Context, userID string) ([]*models.WebauthnCredential, error)
func (r Repository) WebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) (*models.WebauthnCredential, error)
func (r Repository) WebauthnCredentialDelete(ctx context.Context, id string) error
```

## WebAuthn Challenge Methods

Stores in-flight registration/login ceremony challenges. Login challenges are discoverable (usernameless), so no user is known yet — this is why challenges live in their own table with a nullable, unconstrained `user_id` instead of being stored as `Token` rows (whose `user_id` is `NOT NULL` with a foreign key).

```go
func (r Repository) WebauthnChallengeCreate(ctx context.Context, ch *models.WebauthnChallenge) (*models.WebauthnChallenge, error)
func (r Repository) WebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) (*models.WebauthnChallenge, error)
func (r Repository) WebauthnChallengeDelete(ctx context.Context, id string) error
```

## Audit Log Methods

```go
func (r Repository) AuditLogCreate(ctx context.Context, log *models.AuditLog) (*models.AuditLog, error)
func (r Repository) AuditLogListByUserID(ctx context.Context, userID string, filter models.AuditLogFilter, limit, offset int) (logs []*models.AuditLog, hasMore bool, err error)
```

## RBAC Methods

Real RBAC — roles/permissions tables and their `user_roles`/`role_permissions` join tables — separate from the legacy `User.Roles` string field. See [Roles & Permissions (RBAC)](../guides/admin-operations.md#roles--permissions-rbac).

```go
func (r Repository) RoleCreate(ctx context.Context, role *models.Role) (*models.Role, error)
func (r Repository) RoleGetByID(ctx context.Context, id string) (*models.Role, error)
func (r Repository) RoleGetByName(ctx context.Context, name string) (*models.Role, error)
func (r Repository) RolesList(ctx context.Context) ([]*models.Role, error)
func (r Repository) RoleDelete(ctx context.Context, id string) error // cascades user_roles/role_permissions

func (r Repository) PermissionCreate(ctx context.Context, permission *models.Permission) (*models.Permission, error)
func (r Repository) PermissionGetByID(ctx context.Context, id string) (*models.Permission, error)
func (r Repository) PermissionGetByName(ctx context.Context, name string) (*models.Permission, error)
func (r Repository) PermissionsList(ctx context.Context) ([]*models.Permission, error)
func (r Repository) PermissionDelete(ctx context.Context, id string) error // cascades role_permissions

func (r Repository) UserRoleGrant(ctx context.Context, userID, roleID string) error
func (r Repository) UserRoleRevoke(ctx context.Context, userID, roleID string) error
func (r Repository) RolesByUserID(ctx context.Context, userID string) ([]*models.Role, error)

func (r Repository) RolePermissionGrant(ctx context.Context, roleID, permissionID string) error
func (r Repository) RolePermissionRevoke(ctx context.Context, roleID, permissionID string) error
func (r Repository) PermissionsByRoleID(ctx context.Context, roleID string) ([]*models.Permission, error)

// Resolved transitively through every role granted to the user.
func (r Repository) PermissionsByUserID(ctx context.Context, userID string) ([]*models.Permission, error)
```

## Organization Methods

`role_id` on `ezauth_org_members` is a foreign key into `ezauth_roles` — org membership draws from the same role catalog as RBAC. See [Organizations](../guides/admin-operations.md#organizations).

```go
func (r Repository) OrganizationCreate(ctx context.Context, org *models.Organization) (*models.Organization, error)
func (r Repository) OrganizationGetByID(ctx context.Context, id string) (*models.Organization, error)
func (r Repository) OrganizationsList(ctx context.Context, limit, offset int) (orgs []*models.Organization, hasMore bool, err error)
func (r Repository) OrganizationDelete(ctx context.Context, id string) error // cascades org_members

// OrgMemberUpsert inserts, or updates role_id if the (org, user) pair already exists.
func (r Repository) OrgMemberUpsert(ctx context.Context, orgID, userID, roleID string) error
func (r Repository) OrgMemberRemove(ctx context.Context, orgID, userID string) error
func (r Repository) OrgMembersByOrgID(ctx context.Context, orgID string) ([]*models.OrgMember, error) // joined with ezauth_roles for RoleName
func (r Repository) OrganizationsByUserID(ctx context.Context, userID string) ([]*models.Organization, error)
```
