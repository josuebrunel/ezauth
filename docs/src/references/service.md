# Service Reference

The `service.Auth` struct contains the core business logic for authentication. It is independent of the HTTP layer.

```go
type Auth struct {
    Cfg    *config.Config
    Repo   *repository.Repository
    Mailer Mailer
    // ...
}
```

## Constructor

### `New`

Creates a new `Auth` service. Returns an error if `cfg.JWT` (or `cfg.JWTSecret`, for the default HS256 mode) describes invalid JWT signing configuration — e.g. an unsupported algorithm or unparsable PEM key.

```go
func New(cfg *config.Config, repo *repository.Repository, pathPrefix string) (*Auth, error)
```

### `NewFromConfig`

Creates a new `Auth` service and initializes the repository connection based on the config.

```go
func NewFromConfig(cfg *config.Config, pathPrefix string) (*Auth, error)
```

## User Operations

### `UserCreate`

Creates a new user. It hashes the password, validates the password length (min 8 chars), and stores the user in the repository.

```go
func (a *Auth) UserCreate(ctx context.Context, req *RequestBasicAuth) (*models.User, error)
```

### `UserAuthenticate`

Authenticates a user by email and password.

```go
func (a Auth) UserAuthenticate(ctx context.Context, req RequestBasicAuth) (*models.User, error)
```

### `UserUpdatePassword`

Updates a user's password. Enforces password validation rules.

```go
func (a Auth) UserUpdatePassword(ctx context.Context, user *models.User, password string) (*models.User, error)
```

### `UserUpdate`

Updates user profile information.

```go
func (a Auth) UserUpdate(ctx context.Context, user *models.User) (*models.User, error)
```

### `UserDelete`

Deletes a user by their ID.

```go
func (a Auth) UserDelete(ctx context.Context, id string) error
```

## Token Operations

### `TokenCreate`

Generates a new pair of Access Token (JWT) and Refresh Token (Opaque) for a user.

```go
func (a *Auth) TokenCreate(ctx context.Context, user *models.User) (*TokenResponse, error)
```

### `TokenRefresh`

Validates a refresh token and issues a new pair of tokens.

```go
func (a *Auth) TokenRefresh(ctx context.Context, refreshToken string) (*TokenResponse, error)
```

### `TokenRevoke`

Revokes a refresh token immediately.

```go
func (a *Auth) TokenRevoke(ctx context.Context, refreshToken string) error
```

## API Keys

Scopes are stored as a plain string array in the `Token`'s existing `Metadata` column — no separate table. An empty/nil scopes list means unscoped/full access. See [Scoped API Keys](../guides/account-security.md#scoped-api-keys).

```go
func (a *Auth) APIKeyCreate(ctx context.Context, userID string, scopes []string) (*models.Token, error)
func (a *Auth) APIKeyRevoke(ctx context.Context, id string) error
func (a *Auth) APIKeysList(ctx context.Context, userID string) ([]*models.Token, error)
```

## Asymmetric JWT Signing (JWKS)

Configured via `Cfg.JWT` (`Algorithm`, `PrivateKey`, `PublicKey`, `KeyID`, `PreviousPublicKey`, `PreviousKeyID` — see [Configuration](../configuration.md)); defaults to symmetric HS256 (`Cfg.JWTSecret`) when `Cfg.JWT.Algorithm` is unset.

```go
func (a *Auth) JWTKeyFunc() jwt.Keyfunc          // resolves the verification key by the token's "kid" — used by AuthMiddleware
func (a *Auth) JWTSigningMethods() []string      // accepted algorithm(s) for jwt.WithValidMethods
func (a *Auth) JWKS() JWKSet                     // JSON Web Key Set for GET /.well-known/jwks.json; empty for HS256
```

`JWKSet`/`JWK` are RFC 7517 types covering RSA and Ed25519 (OKP) public keys.

## Password Flows

### `PasswordResetRequest`

Generates a reset token and sends it via email.

```go
func (a *Auth) PasswordResetRequest(ctx context.Context, req RequestPasswordReset) error
```

### `PasswordResetConfirm`

Verifies the reset token and updates the user's password.

```go
func (a *Auth) PasswordResetConfirm(ctx context.Context, req RequestPasswordResetConfirm) error
```

### `PasswordlessRequest`

Generates a magic link token and sends it via email.

```go
func (a *Auth) PasswordlessRequest(ctx context.Context, req service.RequestPasswordless) error
```

### `PasswordlessLogin`

Verifies the magic link token and issues authentication tokens.

```go
func (a *Auth) PasswordlessLogin(ctx context.Context, token string) (*TokenResponse, error)
```

## OAuth2

### `RegisterOAuth2Provider`

Registers a custom or preset OAuth2/OIDC provider at runtime (see `pkg/service/providers` for presets and OIDC discovery).

```go
func (a *Auth) RegisterOAuth2Provider(name string, p OAuth2Provider)
```

### `OAuth2GetConfig`

Returns the `*oauth2.Config` for a registered provider.

```go
func (a *Auth) OAuth2GetConfig(provider string) (*oauth2.Config, error)
```

### `OAuth2GetUserInfo`

Exchanges a provider token for the provider's user info.

```go
func (a *Auth) OAuth2GetUserInfo(ctx context.Context, provider string, token *oauth2.Token) (*OAuth2UserInfo, error)
```

### `OAuth2Authenticate`

Finds or creates a local user from OAuth2 user info, auto-linking to an existing account only when the provider confirms `email_verified: true`.

```go
func (a *Auth) OAuth2Authenticate(ctx context.Context, provider string, userInfo *OAuth2UserInfo) (*models.User, error)
```

## Impersonation

`ezauth` enforces no authorization on who may impersonate — the caller is responsible for checking that the admin is allowed to (e.g. `adminUser.HasRole("admin")`) before calling `Impersonate`.

### `Impersonate`

Mints a new token pair for a target user on behalf of the admin. The resulting access token carries an `act` claim identifying the admin.

```go
func (a *Auth) Impersonate(ctx context.Context, adminUser *models.User, targetUserID string) (*TokenResponse, error)
```

### `StopImpersonating`

Revokes an impersonation refresh token, ending that session.

```go
func (a *Auth) StopImpersonating(ctx context.Context, impersonationRefreshToken string) error
```

## Multi-Factor Authentication (TOTP)

### `MFAEnroll`

Generates a new TOTP secret and provisioning URI for a user; the secret is not persisted until `MFAConfirm` verifies a code.

```go
func (a *Auth) MFAEnroll(ctx context.Context, user *models.User) (*MFAEnrollResponse, error)
```

### `MFAConfirm`

Verifies the enrollment code and enables MFA, returning a set of one-time recovery codes.

```go
func (a *Auth) MFAConfirm(ctx context.Context, user *models.User, code string) ([]string, error)
```

### `MFADisable`

Disables MFA after verifying a current TOTP or recovery code.

```go
func (a *Auth) MFADisable(ctx context.Context, user *models.User, code string) error
```

### `CompleteBasicLogin`

Called after password/OAuth2 authentication succeeds; returns tokens directly if MFA is not enabled or the device is trusted, otherwise returns a pending `mfa_token` for step-up verification.

```go
func (a *Auth) CompleteBasicLogin(ctx context.Context, user *models.User, deviceToken string) (*LoginResponse, error)
```

### `MFALoginVerify`

Completes a step-up login by verifying a TOTP/recovery code against a pending `mfa_token`; optionally issues a trusted-device token.

```go
func (a *Auth) MFALoginVerify(ctx context.Context, mfaToken, code string, rememberDevice bool) (user *models.User, tokens *TokenResponse, deviceToken string, err error)
```

### Trusted Devices

```go
func (a *Auth) TrustDevice(ctx context.Context, user *models.User, name string) (string, error)
func (a *Auth) IsTrustedDevice(ctx context.Context, user *models.User, deviceToken string) bool
func (a *Auth) TrustedDevices(ctx context.Context, userID string) ([]TrustedDeviceInfo, error)
func (a *Auth) RevokeTrustedDevice(ctx context.Context, user *models.User, deviceID string) error
```

## Sessions

Each refresh token issued to a user is a session (one per login/device). `RevokeAllSessions`'s `exceptSessionID` keeps the named session — pass `""` to log out everywhere.

```go
func (a *Auth) Sessions(ctx context.Context, userID string) ([]SessionInfo, error)
func (a *Auth) RevokeSession(ctx context.Context, user *models.User, sessionID string) error
func (a *Auth) RevokeAllSessions(ctx context.Context, user *models.User, exceptSessionID string) error
```

## WebAuthn / Passkeys

### Registration

```go
func (a *Auth) WebauthnBeginRegistration(ctx context.Context, user *models.User) (*protocol.CredentialCreation, string, error)
func (a *Auth) WebauthnFinishRegistration(ctx context.Context, user *models.User, sessionKey string, r *http.Request, name string) (*models.WebauthnCredential, error)
```

### Login

Discoverable (usernameless) login: no user is known until the authenticator's response is verified, which is why the in-flight challenge is stored in a dedicated `ezauth_webauthn_challenges` table rather than the Tokens table.

```go
func (a *Auth) WebauthnBeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
func (a *Auth) WebauthnFinishLogin(ctx context.Context, sessionKey string, r *http.Request) (*models.User, *TokenResponse, error)
```

### Managing Credentials

```go
func (a *Auth) WebauthnCredentials(ctx context.Context, userID string) ([]*models.WebauthnCredential, error)
func (a *Auth) WebauthnDeleteCredential(ctx context.Context, user *models.User, credentialRecordID string) error
```

## SMS OTP

### `SMSOTPRequest`

Generates and sends an OTP code via the configured `SMSSender`. Creates a placeholder user (with a synthetic `phone+"@phone.invalid"` email) on first use by a new phone number.

```go
func (a *Auth) SMSOTPRequest(ctx context.Context, req RequestSMSOTP) error
```

### `SMSOTPVerify`

Verifies the code and issues authentication tokens.

```go
func (a *Auth) SMSOTPVerify(ctx context.Context, req RequestSMSOTPVerify) (*TokenResponse, error)
```

## Invitation-Based Onboarding

`ezauth` enforces no authorization on who may invite — same stance as `Impersonate`.

```go
func (a *Auth) InvitationCreate(ctx context.Context, inviter *models.User, req RequestInvitation) (*InvitationInfo, error)
func (a *Auth) InvitationPreview(ctx context.Context, tokenValue string) (*InvitationInfo, error)
func (a *Auth) InvitationAccept(ctx context.Context, req RequestInvitationAccept) (*models.User, *TokenResponse, error)
func (a *Auth) Invitations(ctx context.Context, inviterID string) ([]InvitationInfo, error)
func (a *Auth) InvitationRevoke(ctx context.Context, inviter *models.User, invitationID string) error
```

## Guarded Email Change

### `EmailChangeRequest`

Requires the current password; sends a confirmation link to the new address and a notice to the old one.

```go
func (a *Auth) EmailChangeRequest(ctx context.Context, user *models.User, req RequestEmailChange) error
```

### `EmailChangeConfirm`

Applies the change and revokes every other session.

```go
func (a *Auth) EmailChangeConfirm(ctx context.Context, tokenValue string) (*models.User, error)
```

## Admin User Management

`ezauth` enforces no authorization on who may call these — same stance as `Impersonate`.

### `UsersList`

Search/filter/paginate users. Supports `Search` (email/username substring, case-insensitive across all 3 dialects), `Status` (`UserStatusActive`/`Locked`/`Suspended`), `CreatedAfter`/`CreatedBefore`, `LastActiveAfter`/`LastActiveBefore`, `Limit`/`Offset`. Returned users have `PasswordHash` stripped.

```go
func (a *Auth) UsersList(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error)
```

### `UserSuspend` / `UserReactivate`

Suspend deactivates a user's account with no auto-expiry (distinct from a brute-force lockout); reactivate re-enables a suspended or locked-out account.

```go
func (a *Auth) UserSuspend(ctx context.Context, userID string) (*models.User, error)
func (a *Auth) UserReactivate(ctx context.Context, userID string) (*models.User, error)
```

### `UserAuthHistory`

Returns the user's most recent authentication-related token events, newest first. A lightweight proxy built from the Tokens table — see `AuditLogs` below for a real persisted audit trail.

```go
func (a *Auth) UserAuthHistory(ctx context.Context, userID string, limit int) ([]AuthHistoryEntry, error)
```

## Audit Log

`ezauth` persists a row to an audit log for security-relevant events (login success/failure, password reset, impersonation, account lockout, MFA, user create/delete) automatically, via a built-in hook that wraps whatever `Hook` you register — see [Hooks](../guides/admin-operations.md#hooks). Enabled by default; disable with `EZAUTH_AUDIT_LOG_ENABLED=false`.

```go
func (a *Auth) AuditLogs(ctx context.Context, userID string, opts ListAuditLogsOptions) (*ListAuditLogsResult, error)
```

`ListAuditLogsOptions` supports `EventType` (a `models.AuditEvent*` constant), `Since`/`Until` (`*time.Time`), and `Limit`/`Offset` (default 50, max 200). `ezauth` enforces no authorization on who may call this — same stance as `UsersList`.

## Roles & Permissions (RBAC)

Real RBAC — separate from, and additive to, the legacy `User.Roles` string field and its `HasRole`/`AddRole`/etc. helpers. See [Roles & Permissions (RBAC)](../guides/admin-operations.md#roles--permissions-rbac).

```go
func (a *Auth) RoleCreate(ctx context.Context, name, description string) (*models.Role, error)
func (a *Auth) RolesList(ctx context.Context) ([]*models.Role, error)
func (a *Auth) RoleDelete(ctx context.Context, id string) error

func (a *Auth) PermissionCreate(ctx context.Context, name, description string) (*models.Permission, error)
func (a *Auth) PermissionsList(ctx context.Context) ([]*models.Permission, error)
func (a *Auth) PermissionDelete(ctx context.Context, id string) error

// Idempotent; each records an AuditEventRoleGranted/AuditEventRoleRevoked audit event.
func (a *Auth) UserRoleGrant(ctx context.Context, userID, roleName string) error
func (a *Auth) UserRoleRevoke(ctx context.Context, userID, roleName string) error

func (a *Auth) RolePermissionGrant(ctx context.Context, roleName, permissionName string) error
func (a *Auth) RolePermissionRevoke(ctx context.Context, roleName, permissionName string) error

func (a *Auth) UserRolesList(ctx context.Context, userID string) ([]*models.Role, error)
func (a *Auth) UserHasRole(ctx context.Context, userID, roleName string) (bool, error)
func (a *Auth) UserHasPermission(ctx context.Context, userID, permissionName string) (bool, error) // resolved transitively through the user's roles
```

## Organizations

Lightweight multi-tenancy. Each member's role is drawn from the RBAC role catalog above. See [Organizations](../guides/admin-operations.md#organizations).

```go
func (a *Auth) OrganizationCreate(ctx context.Context, name string) (*models.Organization, error)
func (a *Auth) OrganizationGetByID(ctx context.Context, id string) (*models.Organization, error)
func (a *Auth) OrganizationsList(ctx context.Context, opts ListOrganizationsOptions) (*ListOrganizationsResult, error) // paginated (Limit default 50, max 200)
func (a *Auth) OrganizationDelete(ctx context.Context, id string) error // cascades org_members

// OrgMemberAdd upserts: calling it again for the same (org, user) updates the role.
func (a *Auth) OrgMemberAdd(ctx context.Context, orgID, userID, roleName string) error
func (a *Auth) OrgMemberRemove(ctx context.Context, orgID, userID string) error
func (a *Auth) OrgMembersList(ctx context.Context, orgID string) ([]*models.OrgMember, error) // RoleName joined in
func (a *Auth) UserOrganizationsList(ctx context.Context, userID string) ([]*models.Organization, error)
```
