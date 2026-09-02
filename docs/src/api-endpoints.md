# API Endpoints

`ezauth` provides two sets of endpoints:

1.  **Form Handlers (`/auth/*`)**: Designed for browser clients. They handle redirects, use HTTP-only cookies for sessions, and require CSRF protection for POST requests.
2.  **JSON API (`/auth/api/*`)**: Designed for mobile apps or SPAs. They return JSON responses and require API Key authentication.

All `ezauth` JSON API responses follow a consistent format:

```json
{
  "error": "Error message if any, else null",
  "data": "The actual response data"
}
```

## Well-Known Endpoints

`GET /.well-known/jwks.json` — served at the domain root, outside both prefixes above, per the well-known-URI convention. Publishes the JSON Web Key Set for the current (and, during a rotation, previous) asymmetric access-token signing key — see [Asymmetric JWT Signing (JWKS)](library.md#asymmetric-jwt-signing-jwks). Returns `{"keys": []}` when signing with the default symmetric HS256 algorithm (no API key required).

## Form Handlers (Browser)

These endpoints accept `application/x-www-form-urlencoded` and redirect upon success or failure. Authentication tokens are stored in an HTTP-only cookie named `ezauthsess`.

POST requests to these endpoints are automatically protected by `filippo.io/csrf/gorilla` using modern browser **Fetch Metadata headers** (e.g., `Sec-Fetch-Site: same-origin`). You do not need to manually include a CSRF token in your requests.

### Get CSRF Token
`GET /auth/csrf`

*Available for legacy compatibility only. Tokens are ignored by the server during validation.* Returns a dummy JSON object containing a CSRF token.

**Response:**
```json
{ "csrf_token": "..." }
```

### Register (Form)
`POST /auth/register`
`GET /auth/register` (Redirects to configured Register Page)

**Parameters:**
*   `email` (required)
*   `password` (required)
*   `password_confirm` (required, must match password)
*   `username` (optional)
*   `first_name` (optional)
*   `last_name` (optional)
*   `meta_*` (Optional, any field prefixed with `meta_` will be stored in `UserMetadata`)

### Login (Form)
`POST /auth/login`
`GET /auth/login` (Redirects to configured Login Page)

**Parameters:**
*   `email` (required)
*   `password` (required)

### Logout (Form)
`POST /auth/logout`

### Password Reset (Form)
`POST /auth/password-reset/request`
`POST /auth/password-reset/confirm`

### Passwordless (Form)
`POST /auth/passwordless/request`
`GET /auth/passwordless/login?token=...`

### SMS OTP (Form)
`POST /auth/sms-otp/request` (field: `phone`)
`POST /auth/sms-otp/verify` (fields: `phone`, `code`)

### MFA (Form)
`GET /auth/mfa/verify` (Redirects to `Pages.MFAVerify`)
`POST /auth/mfa/login/verify` (Completes a step-up login using the session-stashed `mfa_token`; a `remember_device` field sets the trusted-device cookie)
`POST /auth/mfa/enroll`, `POST /auth/mfa/confirm`, `POST /auth/mfa/disable` (Require a logged-in session)
`GET /auth/trusted-devices`, `DELETE /auth/trusted-devices/{id}` (Require a logged-in session)

### WebAuthn / Passkeys (Form)
`POST /auth/webauthn/login/begin`, `POST /auth/webauthn/login/finish?session_key=...` (No prior auth required; `login/finish` sets auth cookies and returns `{"redirect": "..."}`)
`POST /auth/webauthn/register/begin`, `POST /auth/webauthn/register/finish?session_key=...&name=...` (Require a logged-in session)
`GET /auth/webauthn/credentials`, `DELETE /auth/webauthn/credentials/{id}` (Require a logged-in session)

Like `GET /auth/csrf`, these return JSON rather than redirecting — WebAuthn ceremonies always require client-side JavaScript (`navigator.credentials.create()`/`.get()`). The request body for `*/finish` endpoints must be the browser's raw response verbatim.

### Sessions (Form)
`GET /auth/sessions` (Require a logged-in session)
`DELETE /auth/sessions/{id}` (Revokes one session; requires a logged-in session)
`DELETE /auth/sessions?except={id}` (Revokes all sessions except `except`, or everywhere if omitted; requires a logged-in session)

### Invitations (Form)
`GET /auth/invitation/accept` (Redirects to `Pages.InvitationAccept`, preserving `?token=...`)
`POST /auth/invitation/accept` (fields: `token`, `password`, `password_confirm`, plus optional `username`/`first_name`/`last_name`/`locale`/`timezone`; sets auth cookies)
`POST /auth/invitations` (fields: `email`, optional `roles`; requires a logged-in session)
`GET /auth/invitations`, `DELETE /auth/invitations/{id}` (Require a logged-in session)
`GET /auth/invitations/preview?token=...` (No auth required; returns JSON)

### Email Change (Form)
`POST /auth/email-change/request` (fields: `current_password`, `new_email`; requires a logged-in session)
`GET /auth/email-change/confirm?token=...` (No auth required; applies the change, clears the session, and redirects to `Pages.Login`)

### Admin User Management (Form)
`GET /auth/admin/users` (Query params: `search`, `status`, `created_after`/`created_before`, `last_active_after`/`last_active_before`, `limit`/`offset`; requires a logged-in session)
`POST /auth/admin/users/{id}/suspend`, `POST /auth/admin/users/{id}/reactivate` (Require a logged-in session)
`GET /auth/admin/users/{id}/history` (Query param: `limit`; requires a logged-in session)
`GET /auth/admin/users/{id}/audit-logs` (Query params: `event_type`, `since`/`until`, `limit`/`offset`; requires a logged-in session)

ezauth enforces no authorization on who may call these — same stance as impersonation. Protect these routes with your own admin-only check before exposing them.

### Impersonation (Form)
`POST /auth/impersonate` (field: `target_user_id`; requires a logged-in session; swaps the session cookie over to the target user, stashing the admin's own tokens)
`POST /auth/impersonate/stop` (Requires an active impersonation session; restores the admin's own stashed session — no re-login required)

ezauth enforces no authorization on who may call `/auth/impersonate` — protect it with your own admin-only check before exposing it.

### OAuth2
`GET /auth/oauth2/{provider}/login` (Initiates login)
`GET /auth/oauth2/{provider}/callback` (Callback handler. URL: `{base_url}/auth/oauth2/{provider}/callback`)

The `{provider}` parameter accepts any built-in provider (google, github, facebook, discord, gitlab, slack, linkedin, spotify) or any registered custom provider.

---

## JSON API Endpoints (`/api`)

All these endpoints require a valid API Key passed via the `X-API-Key` header.

### Register
`POST /auth/api/register`

Creates a new user and returns authentication tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "yourpassword",
  "username": "johndoe",
  "first_name": "John",
  "last_name": "Doe",
  "locale": "en-US",
  "timezone": "UTC",
  "roles": "user,admin",
  "data": {
    "key": "value"
  }
}
```

**Response Data:**
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### Login
`POST /auth/api/login`

Authenticates a user and returns tokens. If the client has a stored trusted-device token (see [Trusted Devices](#trusted-devices)), send it via the `X-Device-Token` header to skip MFA step-up.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "yourpassword"
}
```

**Response Data:** Same as Register, unless the account has TOTP MFA enabled, in which case:
```json
{
  "mfa_required": true,
  "mfa_token": "..."
}
```

Returns `401` with a distinct error message (rather than the generic "invalid email or password") if the account is locked from too many failed attempts, or disabled some other way — see [Account Lockout](#account-lockout).
Exchange `mfa_token` via `POST /auth/api/mfa/login/verify` (see below) to receive real session tokens.

### Refresh Token
`POST /auth/api/token/refresh`

Exchange a refresh token for a new set of tokens (access and refresh).

**Request Body:**
```json
{
  "refresh_token": "..."
}
```

**Response Data:** Same as Register.

### Password Reset Request
`POST /auth/api/password-reset/request`

Sends a password reset link to the user's email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

### Password Reset Confirm
`POST /auth/api/password-reset/confirm`

Resets the user's password using a token received via email.

**Request Body:**
```json
{
  "token": "...",
  "password": "newpassword"
}
```

### Passwordless Request (Magic Link)
`POST /auth/api/passwordless/request`

Sends a magic login link to the user's email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

### Passwordless Login
`GET /auth/api/passwordless/login?token=...`

Authenticates a user using a magic link token.

**Response Data:** Same as Register.

### SMS OTP Request
`POST /auth/api/sms-otp/request`

Sends a one-time login code to the given phone number. An unrecognized phone number gets a temporary, unverified account (same as an unrecognized email does for Passwordless Request).

**Request Body:**
```json
{
  "phone": "+15551234567"
}
```

### SMS OTP Verify
`POST /auth/api/sms-otp/verify`

Authenticates a user using the one-time code sent via SMS. On success, the phone number is marked verified.

**Request Body:**
```json
{
  "phone": "+15551234567",
  "code": "123456"
}
```

**Response Data:** Same as Register.

### MFA Login Verify
`POST /auth/api/mfa/login/verify`

Completes a step-up login started by Login when the account has MFA enabled. Set `remember_device` to also mark the device trusted, skipping MFA step-up on future logins for `EZAUTH_TRUSTED_DEVICE_TTL`.

**Request Body:**
```json
{
  "mfa_token": "...",
  "code": "123456",
  "remember_device": false
}
```

**Response Data:** Same as Register, plus `device_token` when `remember_device` was set — send it back via the `X-Device-Token` header on a future Login request to skip MFA step-up.

### Trusted Devices
`GET /auth/api/trusted-devices` (Protected) — lists the authenticated user's trusted devices.
`DELETE /auth/api/trusted-devices/{id}` (Protected) — revokes one by its record ID.

### Sessions
`GET /auth/api/sessions` (Protected) — lists the authenticated user's active refresh-token sessions (one per logged-in device/client), most recent first.
`DELETE /auth/api/sessions/{id}` (Protected) — revokes one session by its record ID, logging that device out immediately.
`DELETE /auth/api/sessions?except={id}` (Protected) — revokes all sessions except the one named by `except` ("log out other devices"); omit `except` to log out everywhere.

### WebAuthn Login Begin
`POST /auth/api/webauthn/login/begin`

Begins a discoverable (usernameless) WebAuthn login ceremony. No request body needed.

**Response Data:**
```json
{
  "publicKey": { "challenge": "...", "rpId": "...", "...": "..." },
  "session_key": "..."
}
```
`publicKey` (renamed from the top-level object per the WebAuthn spec) is passed to `navigator.credentials.get()` in the browser.

### WebAuthn Login Finish
`POST /auth/api/webauthn/login/finish?session_key=...`

**Request Body:** the raw JSON returned by `navigator.credentials.get()`, forwarded verbatim.

**Response Data:** Same as Register.

### Invitation Preview
`GET /auth/api/invitations/preview?token=...`

Looks up a pending invitation by its token, e.g. to prefill a registration form. No authentication required.

**Response Data:**
```json
{
  "id": "...",
  "email": "newperson@example.com",
  "roles": "member",
  "data": {"org_id": "org-123"},
  "created_at": "...",
  "expires_at": "..."
}
```

### Invitation Accept
`POST /auth/api/invitations/accept`

Completes registration for an invitation: creates the invitee's account with the invitation's pre-verified email and roles, and returns session tokens.

**Request Body:**
```json
{
  "token": "...",
  "password": "their-chosen-password",
  "username": "optional"
}
```

**Response Data:** Same as Register.

## Protected Endpoints

These endpoints require an `Authorization: Bearer <access_token>` header (in addition to `X-API-Key`).

### User Info
`GET /auth/api/userinfo`

Returns the profile information for the currently authenticated user.

**Response Data:**
```json
{
  "id": "...",
  "email": "user@example.com",
  "username": "johndoe",
  "provider": "local",
  "email_verified": true,
  "first_name": "John",
  "last_name": "Doe",
  "roles": "user,admin",
  "created_at": "...",
  "updated_at": "..."
}
```

### Logout
`POST /auth/api/logout`

Revokes the provided refresh token.

**Request Body:**
```json
{
  "refresh_token": "..."
}
```

### Delete User
`DELETE /auth/api/user`

Deletes the currently authenticated user's account.

### MFA Enroll
`POST /auth/api/mfa/enroll`

Begins TOTP enrollment, generating a new secret. MFA is not enabled until confirmed.

**Response Data:**
```json
{
  "secret": "...",
  "otpauth_url": "otpauth://totp/EzAuth:user@example.com?secret=...&issuer=EzAuth"
}
```

### MFA Confirm
`POST /auth/api/mfa/confirm`

Validates a TOTP code against the pending secret and enables MFA.

**Request Body:**
```json
{
  "code": "123456"
}
```

**Response Data:**
```json
{
  "recovery_codes": ["ab12-cd34", "..."]
}
```

### MFA Disable
`POST /auth/api/mfa/disable`

Disables MFA after validating a TOTP or recovery code.

**Request Body:**
```json
{
  "code": "123456"
}
```

### WebAuthn Register Begin
`POST /auth/api/webauthn/register/begin`

Begins a passkey registration ceremony for the authenticated user. No request body needed.

**Response Data:**
```json
{
  "publicKey": { "challenge": "...", "rp": "...", "user": "...", "...": "..." },
  "session_key": "..."
}
```
`publicKey` is passed to `navigator.credentials.create()` in the browser.

### WebAuthn Register Finish
`POST /auth/api/webauthn/register/finish?session_key=...&name=...`

**Request Body:** the raw JSON returned by `navigator.credentials.create()`, forwarded verbatim. `name` is an optional label for the credential (e.g. "YubiKey 5").

**Response Data:** the persisted credential record (`id`, `sign_count`, `transports`, `name`, `created_at`, ...).

### WebAuthn Credentials List
`GET /auth/api/webauthn/credentials`

Lists the authenticated user's registered passkeys.

### WebAuthn Credential Delete
`DELETE /auth/api/webauthn/credentials/{id}`

Deletes one of the authenticated user's passkeys, identified by its credential record ID (not the raw WebAuthn credential ID).

### Invitation Create
`POST /auth/api/invitations`

Issues a new invitation and emails the invitee a link to accept it. `ezauth` enforces no authorization on who may invite — check that yourself (e.g. `caller.HasRole("admin")`) before calling this.

**Request Body:**
```json
{
  "email": "newperson@example.com",
  "roles": "member",
  "data": {"org_id": "org-123"}
}
```

**Response Data:** the created invitation (same shape as [Invitation Preview](#invitation-preview), without a `data` leak beyond what the caller supplied).

### Invitations List
`GET /auth/api/invitations`

Lists the invitations issued by the authenticated user.

### Invitation Revoke
`DELETE /auth/api/invitations/{id}`

Revokes one of the authenticated user's invitations by its record ID.

### Email Change Request
`POST /auth/api/email-change/request`

Requires the current password to confirm intent, then emails a verification link to the new address. The account's email doesn't change until confirmed; the old address also gets a notice of the request.

**Request Body:**
```json
{
  "current_password": "...",
  "new_email": "new-address@example.com"
}
```

### Email Change Confirm
`GET /auth/api/email-change/confirm?token=...`

Applies the requested email change and revokes every other session. No authentication required (the token itself is the credential).

**Response Data:** the updated user profile (same shape as User Info).

### Impersonate
`POST /auth/api/impersonate`

Mints a new token pair for a target user on behalf of the authenticated caller (the "admin"). ezauth enforces no authorization on who may call this — protect it with your own admin-only check (e.g. `adminUser.HasRole("admin")`) before exposing it. Fails with `400` if the caller is already impersonating someone (stop that session first).

**Request Body:**
```json
{
  "target_user_id": "usr_123",
  "refresh_token": "<the admin's own current refresh token>"
}
```

`refresh_token` is the admin's own refresh token, echoed back unchanged as `original_refresh_token` so a stateless JSON client can restore its own session later via `/auth/api/impersonate/stop`.

**Response Data:**
```json
{
  "access_token": "<new access token, authenticated as the target user>",
  "refresh_token": "<new refresh token, authenticated as the target user>",
  "expires_in": 3600,
  "token_type": "Bearer",
  "original_access_token": "<the admin's own access token, unchanged>",
  "original_refresh_token": "<the admin's own refresh token, unchanged>",
  "impersonator_id": "usr_admin",
  "target_user_id": "usr_123"
}
```

The new `access_token` carries an `act` claim identifying the impersonator; use `ezauth.GetImpersonatorID(ctx)` to read it.

### Stop Impersonation
`POST /auth/api/impersonate/stop`

Revokes an impersonation refresh token, ending that session. Call it with the impersonation token pair (not the admin's original one).

**Request Body:**
```json
{
  "refresh_token": "<the impersonation refresh token to revoke>"
}
```

**Response Data:**
```json
{"message": "impersonation ended"}
```

### Admin: List/Search Users
`GET /auth/api/admin/users`

ezauth enforces no authorization on who may call this — same stance as impersonation. Protect this route with your own admin-only check before exposing it.

**Query Parameters:**
| Param | Description |
| --- | --- |
| `search` | Substring match against email or username |
| `status` | `active`, `locked`, or `suspended` |
| `created_after` / `created_before` | RFC3339 timestamp, filters by account creation time |
| `last_active_after` / `last_active_before` | RFC3339 timestamp, filters by last-active time |
| `limit` | Page size (default 20, max 100) |
| `offset` | Page offset |

**Response Data:**
```json
{
  "users": [{"id": "...", "email": "...", "..." : "..."}],
  "has_more": false
}
```

### Admin: Suspend User
`POST /auth/api/admin/users/{id}/suspend`

Deactivates the user's account (`IsActive` cleared, no auto-expiry — distinct from a brute-force lockout).

### Admin: Reactivate User
`POST /auth/api/admin/users/{id}/reactivate`

Re-enables a suspended or locked-out account and clears any lockout bookkeeping.

### Admin: User Auth History
`GET /auth/api/admin/users/{id}/history`

Returns the user's most recent authentication-related token events (logins, password resets, MFA step-ups, ...), newest first. A lightweight proxy for a proper audit log, not a full audit trail.

**Query Parameters:** `limit` (default 50, max 200)

**Response Data:**
```json
[
  {"token_type": "refresh", "created_at": "...", "expires_at": "...", "revoked": false}
]
```

### Admin: Audit Logs
`GET /auth/api/admin/users/{id}/audit-logs`

Lists/filters the user's persisted audit log — real named security events (login success/failure, password reset, impersonation, account lockout, MFA, user create/delete), not the token-history proxy above. ezauth enforces no authorization on who may call this — same stance as the rest of Admin User Management.

**Query Parameters:**
| Param | Description |
| --- | --- |
| `event_type` | Filter to a single event type, e.g. `login.failed` |
| `since` / `until` | RFC3339 timestamp, filters by event time |
| `limit` | Page size (default 50, max 200) |
| `offset` | Page offset |

**Response Data:**
```json
{
  "events": [{"event_type": "login.failed", "metadata": {"reason": "invalid_password"}, "created_at": "..."}],
  "has_more": false
}
```
