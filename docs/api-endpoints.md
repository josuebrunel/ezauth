# API Endpoints

`ezauth` provides an interactive Swagger UI to explore and test the API. By default, it is available at `/swagger/index.html` when running the service.

## Swagger UI

If you are running the service locally with default settings, you can access the Swagger UI at:
[http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

All `ezauth` responses follow a consistent format:

```json
{
  "error": "Error message if any, else null",
  "data": "The actual response data"
}
```

## Public Endpoints

### Register
`POST /auth/register`

Creates a new user and returns authentication tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "yourpassword",
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
`POST /auth/login`

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
`POST /auth/token/refresh`

Exchange a refresh token for a new set of tokens (access and refresh).

**Request Body:**
```json
{
  "refresh_token": "..."
}
```

**Response Data:** Same as Register.

### Password Reset Request
`POST /auth/password-reset/request`

Sends a password reset link to the user's email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

### Password Reset Confirm
`POST /auth/password-reset/confirm`

Resets the user's password using a token received via email.

**Request Body:**
```json
{
  "token": "...",
  "password": "newpassword"
}
```

### Passwordless Request (Magic Link)
`POST /auth/passwordless/request`

Sends a magic login link to the user's email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

### Passwordless Login
`GET /auth/passwordless/login?token=...`

Authenticates a user using a magic link token.

**Response Data:** Same as Register.

### OAuth2 Login
`GET /auth/oauth2/{provider}/login`

Redirects the user to the OAuth2 provider (google, github, facebook).

### OAuth2 Callback
`GET /auth/oauth2/{provider}/callback`

The callback URL handled by `ezauth`. After success, it redirects to the `EZAUTH_OAUTH2_CALLBACK_URL` with the tokens as query parameters.

## Protected Endpoints

These endpoints require an `Authorization: Bearer <access_token>` header.

### User Info
`GET /auth/userinfo`

Returns the profile information for the currently authenticated user.

**Response Data:**
```json
{
  "id": "...",
  "email": "user@example.com",
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
`POST /auth/logout`

Revokes the provided refresh token.

**Request Body:**
```json
{
  "refresh_token": "..."
}
```

### Delete User
`DELETE /auth/user`

Deletes the currently authenticated user's account.
