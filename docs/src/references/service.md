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

Creates a new `Auth` service.

```go
func New(cfg *config.Config, repo *repository.Repository, pathPrefix string) *Auth
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

Returns the user's most recent authentication-related token events, newest first. A lightweight proxy built from the Tokens table, not a full audit log.

```go
func (a *Auth) UserAuthHistory(ctx context.Context, userID string, limit int) ([]AuthHistoryEntry, error)
```
