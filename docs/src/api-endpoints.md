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

### OAuth2
`GET /auth/oauth2/{provider}/login` (Initiates login)
`GET /auth/oauth2/{provider}/callback` (Callback handler. URL: `{base_url}/auth/oauth2/{provider}/callback`)

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

**Response Data:** Same as Register.

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
