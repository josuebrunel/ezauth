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
`POST /auth/mfa/login/verify` (Completes a step-up login using the session-stashed `mfa_token`)
`POST /auth/mfa/enroll`, `POST /auth/mfa/confirm`, `POST /auth/mfa/disable` (Require a logged-in session)

### WebAuthn / Passkeys (Form)
`POST /auth/webauthn/login/begin`, `POST /auth/webauthn/login/finish?session_key=...` (No prior auth required; `login/finish` sets auth cookies and returns `{"redirect": "..."}`)
`POST /auth/webauthn/register/begin`, `POST /auth/webauthn/register/finish?session_key=...&name=...` (Require a logged-in session)
`GET /auth/webauthn/credentials`, `DELETE /auth/webauthn/credentials/{id}` (Require a logged-in session)

Like `GET /auth/csrf`, these return JSON rather than redirecting — WebAuthn ceremonies always require client-side JavaScript (`navigator.credentials.create()`/`.get()`). The request body for `*/finish` endpoints must be the browser's raw response verbatim.

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

Authenticates a user and returns tokens.

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

Completes a step-up login started by Login when the account has MFA enabled.

**Request Body:**
```json
{
  "mfa_token": "...",
  "code": "123456"
}
```

**Response Data:** Same as Register.

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
