# Handler Reference

The `Handler` struct is responsible for handling all HTTP requests for `ezauth`. It uses `chi` for routing.

```go
type Handler struct {
    // contains filtered or unexported fields
	Session *scs.SessionManager
}
```

## Constructor

### `New`

Creates a new `Handler` instance.

```go
func New(svc *service.Auth, path string, options ...HandlerOption) *Handler
```

- **svc**: The `service.Auth` instance.
- **path**: The base path for the auth routes (e.g., "/auth").
- **options**: Functional options for configuration.

## Methods

### `Run`

Starts the HTTP server on the address configured in `service.Config`.

```go
func (h *Handler) Run()
```

### `ServeHTTP`

Implements the `http.Handler` interface, allowing the `Handler` to be mounted on any Go HTTP router.

```go
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

### `GetSessionUser`

Retrieves the authenticated user. It checks:

1.  Context (if `LoadUserMiddleware` was used)
2.  Session Cookies (extracts tokens and verifies with DB)

```go
func (h *Handler) GetSessionUser(ctx context.Context) (*models.User, error)
```

### `GetSessionTokens`

Retrieves the access and refresh tokens from the session cookies.

```go
func (h *Handler) GetSessionTokens(ctx context.Context) (map[string]string, bool)
```

### `IsAuthenticated`

Checks if the request is authenticated. It returns `true` if a user can be retrieved from the context or session.

```go
func (h *Handler) IsAuthenticated(ctx context.Context) bool
```

## HTTP Handlers

The following methods are attached to routes internally by `New`, but are public if you need to wrap or mock them.

### Auth
-   `Login(w, r)`: JSON Login
-   `Register(w, r)`: JSON Register
-   `Logout(w, r)`: User logout
-   `RefreshToken(w, r)`: Refresh access token
-   `OAuth2Login(w, r)`: Initiate OAuth2 flow
-   `OAuth2Callback(w, r)`: OAuth2 callback handler
-   `JWKS(w, r)`: Serves the JSON Web Key Set at `GET /.well-known/jwks.json` (root-level, outside the path prefix); empty for the default HS256 mode

### User Management
-   `UserInfo(w, r)`: Get current user info
-   `DeleteUser(w, r)`: Delete current user account

### Password Management
-   `PasswordResetRequest(w, r)`: Request password reset link
-   `PasswordResetConfirm(w, r)`: Confirm password reset
-   `PasswordlessRequest(w, r)`: Request magic link
-   `PasswordlessLogin(w, r)`: Login via magic link

### Impersonation
`ezauth` enforces no authorization here — protect these with your own admin-only check.
-   `Impersonate(w, r)`: Start impersonating a target user (JSON)
-   `StopImpersonation(w, r)`: End an impersonation session (JSON)
-   `FormImpersonate(w, r)`: Start impersonating (form; swaps the session cookie)
-   `FormStopImpersonation(w, r)`: End impersonation (form; restores the admin's own session)
-   `CurrentImpersonatorID(ctx)`, `CurrentImpersonator(ctx)`: Detect impersonation regardless of transport (checks cookie-mode `IsImpersonating` first, then the Bearer/JWT `act` claim)

### Multi-Factor Authentication (TOTP)
-   `MFAEnroll(w, r)`: Generate a TOTP secret + provisioning URI (JSON)
-   `MFAConfirm(w, r)`: Verify enrollment code, enable MFA, return recovery codes (JSON)
-   `MFADisable(w, r)`: Disable MFA (JSON)
-   `MFALoginVerify(w, r)`: Complete a step-up login with a TOTP/recovery code (JSON)
-   `FormMFAEnroll(w, r)`, `FormMFAConfirm(w, r)`, `FormMFADisable(w, r)`, `FormMFALoginVerify(w, r)`: Form equivalents

### Trusted Devices
-   `TrustedDevicesList(w, r)`, `TrustedDeviceRevoke(w, r)`: JSON
-   `FormTrustedDevicesList(w, r)`, `FormTrustedDeviceRevoke(w, r)`: Form equivalents

### Sessions
-   `SessionsList(w, r)`, `SessionRevoke(w, r)`, `SessionsRevokeAll(w, r)`: List/revoke active refresh-token sessions (JSON)
-   `FormSessionsList(w, r)`, `FormSessionRevoke(w, r)`, `FormSessionsRevokeAll(w, r)`: Form equivalents

### WebAuthn / Passkeys
-   `WebauthnRegisterBegin(w, r)`, `WebauthnRegisterFinish(w, r)`: Register a new credential (JSON)
-   `WebauthnLoginBegin(w, r)`, `WebauthnLoginFinish(w, r)`: Discoverable (usernameless) login (JSON)
-   `WebauthnCredentialsList(w, r)`, `WebauthnCredentialDelete(w, r)`: Manage credentials (JSON)
-   `FormWebauthnRegisterBegin(w, r)`, `FormWebauthnRegisterFinish(w, r)`, `FormWebauthnLoginBegin(w, r)`, `FormWebauthnLoginFinish(w, r)`, `FormWebauthnCredentialsList(w, r)`, `FormWebauthnCredentialDelete(w, r)`: Form equivalents (these return JSON rather than redirecting — WebAuthn ceremonies require client-side JavaScript)

### SMS OTP
-   `SMSOTPRequest(w, r)`, `SMSOTPVerify(w, r)`: JSON
-   `FormSMSOTPRequest(w, r)`, `FormSMSOTPVerify(w, r)`: Form equivalents

### Invitation-Based Onboarding
`ezauth` enforces no authorization on who may invite — same stance as impersonation.
-   `InvitationCreate(w, r)`, `InvitationsList(w, r)`, `InvitationRevoke(w, r)`: Manage invitations (JSON; require a logged-in caller)
-   `InvitationPreview(w, r)`: Look up invite details by token, no auth required (JSON)
-   `InvitationAccept(w, r)`: Accept an invite and set a password (JSON)
-   `FormInvitationCreate(w, r)`, `FormInvitationsList(w, r)`, `FormInvitationRevoke(w, r)`, `FormInvitationAccept(w, r)`: Form equivalents

### Guarded Email Change
-   `EmailChangeRequest(w, r)`: Requires current password; sends a confirmation link (JSON)
-   `EmailChangeConfirm(w, r)`: Applies the change and revokes other sessions (JSON)
-   `FormEmailChangeRequest(w, r)`, `FormEmailChangeConfirm(w, r)`: Form equivalents

### Admin User Management
`ezauth` enforces no authorization on who may call these — same stance as impersonation.
-   `AdminUsersList(w, r)`: Search/filter/paginate users (JSON)
-   `AdminUserSuspend(w, r)`, `AdminUserReactivate(w, r)`: Suspend/reactivate an account (JSON)
-   `AdminUserAuthHistory(w, r)`: View a user's auth history (JSON)
-   `AdminUserAuditLogsList(w, r)`: List/filter a user's persisted audit log (JSON)
-   `FormAdminUsersList(w, r)`, `FormAdminUserSuspend(w, r)`, `FormAdminUserReactivate(w, r)`, `FormAdminUserAuthHistory(w, r)`, `FormAdminUserAuditLogsList(w, r)`: Form equivalents

### Roles & Permissions (RBAC)
`ezauth` enforces no authorization on who may call these — same stance as impersonation. See [Roles & Permissions (RBAC)](../guides/admin-operations.md#roles--permissions-rbac).
-   `RoleCreate(w, r)`, `RolesList(w, r)`, `RoleDelete(w, r)`: Manage roles (JSON)
-   `PermissionCreate(w, r)`, `PermissionsList(w, r)`, `PermissionDelete(w, r)`: Manage permissions (JSON)
-   `UserRoleGrant(w, r)`, `UserRolesList(w, r)`, `UserRoleRevoke(w, r)`: Grant/list/revoke a user's roles (JSON)
-   `RolePermissionGrant(w, r)`, `RolePermissionRevoke(w, r)`: Grant/revoke a permission on a role (JSON)
-   `FormRoleCreate(w, r)`, `FormRolesList(w, r)`, `FormRoleDelete(w, r)`, `FormPermissionCreate(w, r)`, `FormPermissionsList(w, r)`, `FormPermissionDelete(w, r)`, `FormUserRoleGrant(w, r)`, `FormUserRolesList(w, r)`, `FormUserRoleRevoke(w, r)`, `FormRolePermissionGrant(w, r)`, `FormRolePermissionRevoke(w, r)`: Form equivalents

### Organizations
`ezauth` enforces no authorization on who may call these — same stance as impersonation. See [Organizations](../guides/admin-operations.md#organizations).
-   `OrganizationCreate(w, r)`, `OrganizationsList(w, r)`, `OrganizationGetByID(w, r)`, `OrganizationDelete(w, r)`: Manage organizations (JSON; `OrganizationsList` paginated via `limit`/`offset`)
-   `OrgMemberAdd(w, r)`, `OrgMembersList(w, r)`, `OrgMemberRemove(w, r)`: Manage an organization's members (JSON; `OrgMemberAdd` upserts)
-   `UserOrganizationsList(w, r)`: List the organizations a user belongs to (JSON)
-   `FormOrganizationCreate(w, r)`, `FormOrganizationsList(w, r)`, `FormOrganizationGetByID(w, r)`, `FormOrganizationDelete(w, r)`, `FormOrgMemberAdd(w, r)`, `FormOrgMembersList(w, r)`, `FormOrgMemberRemove(w, r)`, `FormUserOrganizationsList(w, r)`: Form equivalents

### API Keys
Self-service — always scoped to the calling user's own account, no admin path. See [Scoped API Keys](../guides/account-security.md#scoped-api-keys).
-   `APIKeyCreate(w, r)`: Mint a new key, optionally scoped (JSON)
-   `APIKeysList(w, r)`: List the caller's keys, raw value omitted (JSON)
-   `APIKeyRevoke(w, r)`: Revoke one of the caller's keys (JSON)
-   `FormAPIKeyCreate(w, r)`, `FormAPIKeysList(w, r)`, `FormAPIKeyRevoke(w, r)`: Form equivalents

### Form Handlers
These handlers process `application/x-www-form-urlencoded` requests and return HTML redirects.

-   `FormLogin(w, r)`
-   `FormRegister(w, r)` (Supports `username`, `password_confirm`, and `meta_` fields)
-   `FormLogout(w, r)`
-   `FormPasswordResetRequest(w, r)`
-   `FormPasswordResetConfirm(w, r)`
-   `FormPasswordlessRequest(w, r)`
-   `FormPasswordlessLogin(w, r)`
