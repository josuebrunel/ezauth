# ezauth

[![Tests](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml/badge.svg)](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://josuebrunel.github.io/ezauth/)
[![Go Reference](https://pkg.go.dev/badge/github.com/josuebrunel/ezauth.svg)](https://pkg.go.dev/github.com/josuebrunel/ezauth)

Simple and easy to use authentication library for Golang.

`ezauth` can be used as a standalone authentication service or embedded directly into your Go application as a library.

## Features

- Email/Password Authentication (Register, Login)
- JWT based sessions (Access & Refresh Tokens, Refresh Token Rotation)
- Configurable Password Hashing: bcrypt or Argon2id
- Rate Limiting on authentication endpoints
- OAuth2 Support (Google, GitHub, Facebook) and custom/OIDC provider registration
- Password Reset and Passwordless (Magic Link) authentication
- Extended User Profiles (Username, First Name, Last Name, Phone, Avatar, Nickname, Locale, Timezone, Roles, etc.)
- SQLite, PostgreSQL, and MySQL support
- API Key Protection for endpoints
- Built-in Middleware for route protection
- Swagger API Documentation

## Usage

### As a Standalone Service

You can run `ezauth` as a separate service that handles authentication for your microservices.

1. **Configuration**: Set environment variables.
   ```bash
   export EZAUTH_ADDR=":8080"
   export EZAUTH_API_KEY="your-master-api-key"
   export EZAUTH_BASE_URL="http://localhost:8080"
   export EZAUTH_DB_DIALECT="sqlite3"  # or "postgres" or "mysql"
   export EZAUTH_DB_DSN="auth.db"      # for mysql: "user:pass@tcp(localhost:3306)/dbname?parseTime=true"
   export EZAUTH_DB_SCHEMA="public"    # Optional: Database schema (PostgreSQL only)
   export EZAUTH_JWT_SECRET="super-secret-key"
   export EZAUTH_CSRF_SECRET="your-csrf-secret"  # Optional; defaults to JWT_SECRET if not set
   export EZAUTH_HASHING_ALGORITHM="bcrypt"      # Optional; "bcrypt" or "argon2id"
   export EZAUTH_RATE_LIMIT_ENABLED="false"       # Optional; enable rate limiting on auth endpoints

   # SMTP (Optional - for Email features)
   export EZAUTH_SMTP_HOST="smtp.example.com"
   export EZAUTH_SMTP_PORT="587"
   export EZAUTH_SMTP_USER="user@example.com"
   export EZAUTH_SMTP_PASSWORD="password"
   export EZAUTH_SMTP_FROM="noreply@example.com"

   # Email Templates (Optional - customize email content)
   # Uses Go text/template syntax: {{.Link}}, {{.Token}}, {{.Email}}
   export EZAUTH_EMAIL_PASSWORDLESS_SUBJECT="Magic Link Login"
   export EZAUTH_EMAIL_PASSWORDLESS_BODY="Click the following link to login: {{.Link}}"
   export EZAUTH_EMAIL_PASSWORD_RESET_SUBJECT="Password Reset Request"
   export EZAUTH_EMAIL_PASSWORD_RESET_BODY="Click the following link to reset your password: {{.Link}}"

   # Pages & Redirects (For Form-based auth)
   export EZAUTH_REDIRECT_AFTER_LOGIN="/"
   export EZAUTH_REDIRECT_AFTER_REGISTER="/"
   export EZAUTH_LOGIN_PAGE_URL="/login"
   export EZAUTH_REGISTER_PAGE_URL="/register"

    # OAuth2 (Optional)
    export EZAUTH_OAUTH2_CALLBACK_URL="http://localhost:3000/callback"

    # Google
    export EZAUTH_OAUTH2_GOOGLE_CLIENT_ID="your-google-client-id"
    export EZAUTH_OAUTH2_GOOGLE_CLIENT_SECRET="your-google-client-secret"
    export EZAUTH_OAUTH2_GOOGLE_REDIRECT_URL="http://localhost:8080/auth/oauth2/google/callback"
    export EZAUTH_OAUTH2_GOOGLE_SCOPES="email,profile"

    # GitHub
    export EZAUTH_OAUTH2_GITHUB_CLIENT_ID="your-github-client-id"
    export EZAUTH_OAUTH2_GITHUB_CLIENT_SECRET="your-github-client-secret"
    export EZAUTH_OAUTH2_GITHUB_REDIRECT_URL="http://localhost:8080/auth/oauth2/github/callback"
    export EZAUTH_OAUTH2_GITHUB_SCOPES="user:email"

    # Facebook
    export EZAUTH_OAUTH2_FACEBOOK_CLIENT_ID="your-facebook-client-id"
    export EZAUTH_OAUTH2_FACEBOOK_CLIENT_SECRET="your-facebook-client-secret"
    export EZAUTH_OAUTH2_FACEBOOK_REDIRECT_URL="http://localhost:8080/auth/oauth2/facebook/callback"
    export EZAUTH_OAUTH2_FACEBOOK_SCOPES="email"

    # Discord
    export EZAUTH_OAUTH2_DISCORD_CLIENT_ID="your-discord-client-id"
    export EZAUTH_OAUTH2_DISCORD_CLIENT_SECRET="your-discord-client-secret"
    export EZAUTH_OAUTH2_DISCORD_REDIRECT_URL="http://localhost:8080/auth/oauth2/discord/callback"
    export EZAUTH_OAUTH2_DISCORD_SCOPES="identify,email"

    # GitLab
    export EZAUTH_OAUTH2_GITLAB_CLIENT_ID="your-gitlab-client-id"
    export EZAUTH_OAUTH2_GITLAB_CLIENT_SECRET="your-gitlab-client-secret"
    export EZAUTH_OAUTH2_GITLAB_REDIRECT_URL="http://localhost:8080/auth/oauth2/gitlab/callback"
    export EZAUTH_OAUTH2_GITLAB_SCOPES="read_user"

    # Slack
    export EZAUTH_OAUTH2_SLACK_CLIENT_ID="your-slack-client-id"
    export EZAUTH_OAUTH2_SLACK_CLIENT_SECRET="your-slack-client-secret"
    export EZAUTH_OAUTH2_SLACK_REDIRECT_URL="http://localhost:8080/auth/oauth2/slack/callback"
    export EZAUTH_OAUTH2_SLACK_SCOPES="openid,email"

    # LinkedIn
    export EZAUTH_OAUTH2_LINKEDIN_CLIENT_ID="your-linkedin-client-id"
    export EZAUTH_OAUTH2_LINKEDIN_CLIENT_SECRET="your-linkedin-client-secret"
    export EZAUTH_OAUTH2_LINKEDIN_REDIRECT_URL="http://localhost:8080/auth/oauth2/linkedin/callback"
    export EZAUTH_OAUTH2_LINKEDIN_SCOPES="openid,profile,email"

    # Spotify
    export EZAUTH_OAUTH2_SPOTIFY_CLIENT_ID="your-spotify-client-id"
    export EZAUTH_OAUTH2_SPOTIFY_CLIENT_SECRET="your-spotify-client-secret"
    export EZAUTH_OAUTH2_SPOTIFY_REDIRECT_URL="http://localhost:8080/auth/oauth2/spotify/callback"
    export EZAUTH_OAUTH2_SPOTIFY_SCOPES="user-read-email,user-read-private"
   ```

### Custom OAuth2 / OIDC Providers

You can register arbitrary custom providers dynamically via environment variables (Standalone-service mode) or in Go code (Library mode) as shown below.

#### Standalone-service mode (via Env Vars)
1. Add your provider's name to `EZAUTH_OAUTH2_PROVIDERS` (comma-separated).
2. Configure prefix variables for each provider (`EZAUTH_OAUTH2_<NAME>_`):
   - `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URL` (required)
   - `SCOPES` (optional, comma-separated)
   - Either `ISSUER_URL` (for automatic OIDC discovery) or manual endpoint parameters (`AUTH_URL`, `TOKEN_URL`, `USERINFO_URL`, `ID_FIELD` (default `id`), `EMAIL_FIELD` (default `email`)).

#### Library Mode (Go Code)
You can register custom providers programmatically using the `RegisterOAuth2Provider` API. We ship pre-made presets (Discord, Slack, GitLab) and a generic OIDC discovery helper in the optional `github.com/josuebrunel/ezauth/pkg/service/providers` package:

```go
import (
    "github.com/josuebrunel/ezauth/pkg/service/providers"
)

// 1. OIDC Discovery
oktaProvider, err := providers.OIDC(ctx, "https://your-domain.okta.com", "client-id", "client-secret", "http://localhost:8080/auth/oauth2/okta/callback", []string{"openid", "profile", "email"})
if err == nil {
    auth.RegisterOAuth2Provider("okta", oktaProvider)
}

// 2. Out-of-the-box Preset
discordProvider := providers.Discord("client-id", "client-secret", "http://localhost:8080/auth/oauth2/discord/callback")
auth.RegisterOAuth2Provider("discord", discordProvider)
```

2. **Build and Run**:
   Build the binary from `cmd/ezauthapi/main.go`.
   ```bash
   go build -o ezauthapi ./cmd/ezauthapi
   ```
   Then, run the compiled binary:
   ```bash
   ./ezauthapi
   ```

### As a Library

Embed `ezauth` directly into your existing Go application.

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/josuebrunel/ezauth"
    "github.com/josuebrunel/ezauth/pkg/config"
)

func main() {
    // 1. Setup Config
    os.Setenv("EZAUTH_API_KEY", "my-api-key")
    os.Setenv("EZAUTH_JWT_SECRET", "my-jwt-key")
    
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // 2. Initialize EzAuth
    auth, err := ezauth.New(&cfg, "")
    if err != nil {
        log.Fatalf("Failed to initialize auth: %v", err)
    }

    // 3. Run migrations
    if err := auth.Migrate(); err != nil {
        log.Fatalf("Failed to migrate: %v", err)
    }

    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)

    // 4. Add session middleware (handles sessions and user loading)
    r.Use(auth.SessionMiddleware)

    // 5. Mount Auth Routes
    r.Mount("/auth", auth.Handler)

    // Protected Route Example
    r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        // Retrieve the authenticated user
        user, err := auth.GetSessionUser(r.Context())

        if err != nil {
            http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
            return
        }

        w.Write([]byte(fmt.Sprintf("Welcome, %s!", user.Email)))
    })

    http.ListenAndServe(":3000", r)
}
```

> [!IMPORTANT]
> OAuth2 auto-linking requires the provider to return `email_verified: true` in the user info response. If a provider does not return this field (or returns `false`), the user will be prompted to log in with their existing password rather than being automatically linked. This prevents account takeover via unverified email addresses.

## Session Management (Cookies)

When using the Form-based handlers, `ezauth` manages sessions using HTTP-only cookies via the `scs` session manager. The cookie name is `ezauthsess`.

Inside the session, the Access Token and Refresh Token are stored under the key `tokens`.

You can retrieve them in your application using the helper method:

```go
tokens, err := auth.GetSessionTokens(ctx)
if err == nil {
    accessToken := tokens["access_token"]
    refreshToken := tokens["refresh_token"]
    // ...
}
```

### Retrieving the Authenticated User

You can retrieve the full user object from the session using `auth.GetSessionUser(ctx)`.

> [!IMPORTANT]
> You **MUST** mount the session middleware on your router for this to work.

```go
// 1. Mount session middleware
r.Use(auth.SessionMiddleware)

// 2. In your handler
r.Get("/", func(w http.ResponseWriter, r *http.Request) {
    if !auth.IsAuthenticated(r.Context()) {
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    user, _ := auth.GetSessionUser(r.Context())
    fmt.Println("User:", user.Email)
})
```

### Handling Errors and Success Messages

When using form-based handlers, errors and success messages are stored as flash messages in the session. Flash messages are one-time messages that are automatically cleared after being read.

```go
r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
    // Get flash messages (auto-cleared after read)
    errorMsg := auth.GetErrorMessage(r.Context())
    successMsg := auth.GetSuccessMessage(r.Context())

    // Pass to template for display
    data := map[string]string{
        "Error":   errorMsg,
        "Success": successMsg,
    }
    tmpl.Execute(w, data)
})
```

### CSRF Protection

When using the form-based handlers (e.g., `POST /auth/login`), `ezauth` automatically enforces CSRF protection using `filippo.io/csrf/gorilla` and the `EZAUTH_CSRF_SECRET` (falls back to `EZAUTH_JWT_SECRET` with a warning if not set). It is strongly recommended to set a dedicated `EZAUTH_CSRF_SECRET` to keep CSRF and JWT keys separate.

**Note on Tokens vs Headers:** 
This library relies entirely on modern browser **Fetch Metadata headers** (e.g. `Sec-Fetch-Site`, `Origin`) to enforce same-origin requests dynamically, mirroring the upcoming Go 1.25 standard library CSRF protections.

Because of this, **hidden CSRF tokens in your HTML forms are completely optional and ignored during validation.** However, if you are integrating with frontend frameworks or legacy systems that *expect* a token to be present, `ezauth` provides helpers to seamlessly generate dummy tokens to satisfy those requirements:

```go
import "github.com/josuebrunel/ezauth"

// In your custom handler (ensure it's wrapped with the same CSRF middleware as ezauth)
r.Get("/my-custom-login", func(w http.ResponseWriter, r *http.Request) {
    data := map[string]interface{}{
        // Generate a pre-built <input type="hidden"> field
        "csrfField": ezauth.CSRFTemplateField(r),
        
        // Or get the raw string if you need it for AJAX headers (X-CSRF-Token)
        "csrfToken": ezauth.CSRFToken(r), 
    }
    tmpl.Execute(w, data)
})
```

> [!NOTE]
> If you are using the JSON API endpoints (`/auth/api/*`) instead of the web forms, CSRF is disabled automatically since they use standard JWT Bearer Auth without cookies.

## Helper Functions

`ezauth` provides package-level helper functions for convenient access to authentication context, useful in handlers or templates.

> [!IMPORTANT]
> These functions require the appropriate middleware (`SessionMiddleware`, `LoadUserMiddleware`, or `AuthMiddleware`) to be mounted on the router path.

```go
import "github.com/josuebrunel/ezauth"

func MyHandler(w http.ResponseWriter, r *http.Request) {
    // Check if authenticated
    if ezauth.IsAuthenticated(r.Context()) {
        // ...
    }

    // Get User ID (works with both Session and JWT auth)
    userID, err := ezauth.GetUserID(r.Context())

    // Get User Object (requires LoadUserMiddleware or SessionMiddleware)
    user, err := ezauth.GetUser(r.Context())
    if err == nil {
        // Check for role
        if user.HasRole("admin") {
            // ...
        }

        // Get Metadata with type safety
        if theme, ok := models.GetMeta[string](user, "theme"); ok {
            // use theme
        }
    }
}
```

### User Model Helpers

The `User` struct includes helper methods for common operations:

#### Role Helpers
- `HasRole(role string) bool`: Checks if the user has a specific role.
- `HasAnyRole(roles ...string) bool`: Checks if the user has any of the given roles.
- `HasAllRoles(roles ...string) bool`: Checks if the user has all of the given roles.
- `GetRoles() []string`: Returns the user's roles as a slice.
- `AddRole(role string)`: Appends a role (avoids duplicates).
- `RemoveRole(role string)`: Removes a role from the list.

#### Display Helpers
- `FullName() string`: Returns the user's first and last name combined.
- `DisplayName() string`: Returns the best available name (FullName > Username > email local-part).

#### Provider Helpers
- `IsOAuth() bool`: Returns true if the user signed up via an OAuth2 provider.
- `IsLocal() bool`: Returns true if the user signed up with email/password.

#### Security Helpers
- `Sanitize()`: Clears sensitive fields (e.g., `PasswordHash`) before serialization.

#### Metadata Helpers
- `GetMeta[T any](user, key) (T, bool)`: Retrieves a value from `UserMetadata` with type casting.
- `SetMeta(key, value)`: Sets a value in `UserMetadata`.
- `GetAppMeta[T any](user, key) (T, bool)`: Retrieves a value from `AppMetadata`.
- `SetAppMeta(key, value)`: Sets a value in `AppMetadata`.

## API Endpoints

### Form-based Handlers (Cookies & Redirects)

These endpoints accept `application/x-www-form-urlencoded`, set secure cookies, and redirect.

| Method | Endpoint                           | Description                                                                 |
| ------ | ---------------------------------- | --------------------------------------------------------------------------- |
| POST   | `/auth/register`                   | Register a new user                                                         |
| POST   | `/auth/login`                      | Login and set cookies                                                       |
| POST   | `/auth/logout`                     | Clear cookies and logout                                                    |
| POST   | `/auth/impersonate`                | Start impersonating a user (see [Impersonation](#impersonation))            |
| POST   | `/auth/impersonate/stop`           | Stop impersonating and restore the admin's session                          |
| POST   | `/auth/password-reset/request`     | Request password reset link                                                 |
| POST   | `/auth/password-reset/confirm`     | Confirm password reset                                                      |
| POST   | `/auth/passwordless/request`       | Request magic link                                                          |
| GET    | `/auth/passwordless/login`         | Login via magic link                                                        |
| GET    | `/auth/oauth2/{provider}/login`    | Login via OAuth2 provider                                                   |
| GET    | `/auth/oauth2/{provider}/callback` | OAuth2 provider callback. URL: `{base_url}/auth/oauth2/{provider}/callback` |
| GET    | `/auth/mfa/verify`                 | Redirects to `Pages.MFAVerify` (see [Multi-Factor Authentication](#multi-factor-authentication-totp)) |
| POST   | `/auth/mfa/login/verify`           | Complete a step-up login using the session-stashed pre-auth token           |
| POST   | `/auth/mfa/enroll`                 | Begin TOTP enrollment for the logged-in session user                        |
| POST   | `/auth/mfa/confirm`                | Confirm enrollment and enable MFA                                           |
| POST   | `/auth/mfa/disable`                | Disable MFA                                                                 |
| POST   | `/auth/webauthn/login/begin`       | Begin a discoverable WebAuthn login ceremony (see [WebAuthn / Passkeys](#webauthn--passkeys)) |
| POST   | `/auth/webauthn/login/finish`      | Complete a WebAuthn login and set auth cookies                             |
| POST   | `/auth/webauthn/register/begin`    | Begin passkey registration for the logged-in session user                  |
| POST   | `/auth/webauthn/register/finish`   | Complete passkey registration                                              |
| GET    | `/auth/webauthn/credentials`       | List the logged-in session user's passkeys                                 |
| DELETE | `/auth/webauthn/credentials/{id}`  | Delete one of the logged-in session user's passkeys                        |

#### Form Field Reference

| Endpoint                       | Required Fields                         | Optional Fields                                                                                                   |
| :----------------------------- | :-------------------------------------- | :---------------------------------------------------------------------------------------------------------------- |
| `/auth/register`               | `email`, `password`, `password_confirm` | `username`, `first_name`, `last_name`, `locale`, `timezone`, `phone`, `avatar_url`, `nickname`, `roles`, `meta_*` |
| `/auth/login`                  | `email`, `password`                     |                                                                                                                   |
| `/auth/impersonate`            | `target_user_id`                        |                                                                                                                   |
| `/auth/password-reset/request` | `email`                                 |                                                                                                                   |
| `/auth/password-reset/confirm` | `token`, `password`                     |                                                                                                                   |
| `/auth/passwordless/request`   | `email`                                 |                                                                                                                   |
| `/auth/passwordless/login`     | `token` (query param)                   |                                                                                                                   |
| `/auth/mfa/login/verify`       | `code`                                  |                                                                                                                   |
| `/auth/mfa/confirm`            | `code`                                  |                                                                                                                   |
| `/auth/mfa/disable`            | `code`                                  |                                                                                                                   |

> [!NOTE]
> Passwords must be between 8 and 128 characters long. The `/auth/webauthn/*` endpoints are not listed here: they take the browser's raw `navigator.credentials` JSON response as the request body (plus `session_key`/`name` query params), not form-encoded fields — see [WebAuthn / Passkeys](#webauthn--passkeys).

### API Handlers (JSON)

These endpoints accept `application/json` and return JSON responses.

| Method | Endpoint                           | Description                       |
| ------ | ---------------------------------- | --------------------------------- |
| POST   | `/auth/api/register`               | Register a new user               |
| POST   | `/auth/api/login`                  | Login and receive tokens          |
| POST   | `/auth/api/token/refresh`          | Refresh access token              |
| POST   | `/auth/api/password-reset/request` | Request password reset link       |
| POST   | `/auth/api/password-reset/confirm` | Confirm password reset            |
| POST   | `/auth/api/passwordless/request`   | Request magic link                |
| GET    | `/auth/api/passwordless/login`     | Login via magic link              |
| GET    | `/auth/api/userinfo`               | Get current user info (Protected) |
| POST   | `/auth/api/logout`                 | Revoke refresh token (Protected)  |
| POST   | `/auth/api/impersonate`            | Start impersonating a user (Protected, see [Impersonation](#impersonation)) |
| POST   | `/auth/api/impersonate/stop`       | Stop impersonating (Protected)    |
| DELETE | `/auth/api/user`                   | Delete account (Protected)        |
| POST   | `/auth/api/mfa/login/verify`       | Complete a step-up login (see [Multi-Factor Authentication](#multi-factor-authentication-totp)) |
| POST   | `/auth/api/mfa/enroll`             | Begin TOTP enrollment (Protected) |
| POST   | `/auth/api/mfa/confirm`            | Confirm enrollment and enable MFA (Protected) |
| POST   | `/auth/api/mfa/disable`            | Disable MFA (Protected)           |
| POST   | `/auth/api/webauthn/login/begin`   | Begin a discoverable WebAuthn login ceremony (see [WebAuthn / Passkeys](#webauthn--passkeys)) |
| POST   | `/auth/api/webauthn/login/finish`  | Complete a WebAuthn login and receive tokens |
| POST   | `/auth/api/webauthn/register/begin`  | Begin passkey registration (Protected) |
| POST   | `/auth/api/webauthn/register/finish` | Complete passkey registration (Protected) |
| GET    | `/auth/api/webauthn/credentials`     | List the authenticated user's passkeys (Protected) |
| DELETE | `/auth/api/webauthn/credentials/{id}` | Delete one of the authenticated user's passkeys (Protected) |

## Middlewares
 
 `ezauth` provides several "plug and play" middlewares to protect your routes and manage user sessions. These are available directly on the `EzAuth` instance.
 
 ### `auth.SessionMiddleware`
 
 **Usage**: `r.Use(auth.SessionMiddleware)`
 
 This is the recommended middleware for most applications. It combines session management and user loading.
 - Loads and saves session data (cookies).
 - Populates `GetSessionUser(ctx)` for downstream handlers.
 
 ### `auth.LoginRequiredMiddleware`
 
 **Usage**: `r.Use(auth.LoginRequiredMiddleware)`
 
 Protects routes by requiring authentication.
 - **Browser requests**: Redirects to the configured `EZAUTH_LOGIN_PAGE_URL`.
 - **API requests**: Returns `401 Unauthorized`.
 
 ### `auth.LoadUserMiddleware`
 
 **Usage**: `r.Use(auth.LoadUserMiddleware)`
 
 Loads the user into the context *without* managing the session itself. Use this if you are using `auth.Handler.Session.LoadAndSave` manually or have a custom session setup.
 
 ### `auth.AuthMiddleware`
 
 **Usage**: `r.Use(auth.AuthMiddleware)`
 
 Protects API routes using JWT Bearer tokens in the `Authorization` header.
 - Validates the token signature.
 - Sets the user ID in the context.

## Impersonation

`ezauth` supports admin impersonation: an authenticated user can act as another user (e.g. for customer support debugging), then swap back to their own session.

> [!IMPORTANT]
> `ezauth` enforces **no authorization** for who may impersonate. The `Impersonate` method/endpoint mints tokens for any target user on behalf of whoever calls it. Your application is responsible for checking that the caller is allowed to impersonate — e.g. `adminUser.HasRole("admin")` — before calling it in library mode, or by adding your own authorization middleware in front of the `/auth/impersonate` and `/auth/api/impersonate` routes in standalone-service mode.

### Library Mode

```go
// adminUser must already be authenticated; check authorization yourself first.
if !adminUser.HasRole("admin") {
    // reject
}

tokenResp, err := auth.Impersonate(ctx, adminUser, targetUserID)
// tokenResp.AccessToken / tokenResp.RefreshToken now authenticate as targetUser,
// with the access token carrying an "act" claim identifying adminUser.

// ... later, end the impersonation session:
err = auth.StopImpersonating(ctx, tokenResp.RefreshToken)
```

### Standalone-service Mode

Both a JSON API and form-based (cookie) flow are available, mirroring every other endpoint:

```bash
# Start impersonating (JSON API) — requires the admin's own Bearer token.
# refresh_token is the admin's own current refresh token; it's echoed back so the
# client can restore its own session later (the JSON API is stateless).
curl -X POST https://your-host/auth/api/impersonate \
  -H "Authorization: Bearer <admin-access-token>" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id": "<target-id>", "refresh_token": "<admin-refresh-token>"}'

# Stop impersonating — pass the impersonation access/refresh token pair.
curl -X POST https://your-host/auth/api/impersonate/stop \
  -H "Authorization: Bearer <impersonation-access-token>" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<impersonation-refresh-token>"}'
```

For form-based (cookie) clients, `POST /auth/impersonate` (with a `target_user_id` field) swaps the current session cookie over to the target user, stashing the admin's own tokens; `POST /auth/impersonate/stop` restores them — no re-login required.

### Detecting an Impersonation Session

- **Bearer/JWT mode**: `ezauth.GetImpersonatorID(ctx)` returns the acting admin's user ID from the access token's `act` claim (requires `AuthMiddleware`).
- **Cookie/session mode**: `auth.IsImpersonating(ctx)` and `auth.GetImpersonator(ctx)` report whether the current session is an impersonation session and who the acting admin is.

These two are backed by different mechanisms (JWT claims vs. session storage) and aren't interchangeable — use whichever matches how your route is authenticated.

## Multi-Factor Authentication (TOTP)

`ezauth` supports TOTP-based MFA (RFC 6238) — the standard "authenticator app" second factor (Google Authenticator, Authy, 1Password, etc.).

Once a user enables MFA, a successful password login no longer returns session tokens directly: it returns a short-lived `mfa_token` (5 minutes) that must be exchanged for real session tokens via a TOTP or recovery code. This "step-up" flow is enforced by `CompleteBasicLogin`, which `Login`/`FormLogin` call internally.

### Enrollment

```go
// user must already be authenticated.
enroll, err := auth.MFAEnroll(ctx, user)
// enroll.Secret is the raw base32 secret; enroll.OTPAuthURL is an otpauth:// URI
// you can render as a QR code for the user to scan. MFA is NOT enabled yet.

// After the user scans the QR code and enters a code from their app:
recoveryCodes, err := auth.MFAConfirm(ctx, user, code)
// MFA is now enabled. recoveryCodes is a slice of one-time-use plaintext codes —
// show them to the user once; ezauth only ever stores their hashes.
```

### Step-up Login

```go
loginResp, err := auth.CompleteBasicLogin(ctx, user) // user already password-checked
if loginResp.MFARequired {
    // Prompt for a TOTP/recovery code, then:
    user, tokens, err := auth.MFALoginVerify(ctx, loginResp.MFAToken, code)
    // tokens.AccessToken / tokens.RefreshToken authenticate the user.
} else {
    // loginResp.TokenResponse is already a full session — no MFA configured.
}
```

### Disabling

```go
err := auth.MFADisable(ctx, user, code) // accepts a TOTP or recovery code
```

### Standalone-service Mode

```bash
# Login — returns either tokens directly, or {"mfa_required": true, "mfa_token": "..."}.
curl -X POST https://your-host/auth/api/login -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" -d '{"email": "user@example.com", "password": "..."}'

# Complete the step-up login:
curl -X POST https://your-host/auth/api/mfa/login/verify -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" -d '{"mfa_token": "<mfa-token>", "code": "123456"}'

# Enrollment (requires the user's own Bearer token):
curl -X POST https://your-host/auth/api/mfa/enroll -H "Authorization: Bearer <access-token>" -H "X-API-Key: your-api-key"
curl -X POST https://your-host/auth/api/mfa/confirm -H "Authorization: Bearer <access-token>" -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" -d '{"code": "123456"}'
```

For form-based (cookie) clients, `POST /auth/mfa/enroll`, `/auth/mfa/confirm`, and `/auth/mfa/disable` work the same way against the logged-in session user; `FormLogin` redirects to `Pages.MFAVerify` when a step-up is required, stashing the pending `mfa_token` server-side in the session (never exposed to the client) until `POST /auth/mfa/login/verify` completes it. Use `auth.GetMFAEnrollment(ctx)` to read back the pending secret/QR URL for rendering the enrollment page.

Set `EZAUTH_MFA_ISSUER` (default `EzAuth`) to control the issuer name shown in authenticator apps, and `EZAUTH_MFA_VERIFY_PAGE_URL` (default `/mfa/verify`) to point at your own MFA code-entry page.

## WebAuthn / Passkeys

`ezauth` supports WebAuthn/FIDO2 passkey registration and login, as an alternative or complement to password/MFA login. Login is **discoverable (usernameless)**: the browser's platform UI lets the user pick which passkey to use, so no prior email/username is required.

> [!IMPORTANT]
> WebAuthn is disabled unless `EZAUTH_WEBAUTHN_RP_ID` and `EZAUTH_WEBAUTHN_RP_ORIGINS` are both set. `RPID` is the effective domain (e.g. `example.com`, no scheme/port); `RPOrigins` is a comma-separated list of allowed origins (e.g. `https://example.com`). WebAuthn ceremonies always require client-side JavaScript (`navigator.credentials.create()`/`.get()`), regardless of whether the rest of your app uses cookies or Bearer tokens — there is no plain-HTML-form equivalent.

### Registration (Library Mode)

```go
// user must already be authenticated.
creation, sessionKey, err := auth.WebauthnBeginRegistration(ctx, user)
// Send creation (as JSON) to the browser to call navigator.credentials.create(),
// and keep sessionKey to pass to the finish step (e.g. as a query param, or
// stashed in the user's session).

// r is the incoming HTTP request whose body is the browser's raw
// navigator.credentials.create() response, forwarded verbatim.
cred, err := auth.WebauthnFinishRegistration(ctx, user, sessionKey, r, "YubiKey 5")
```

### Login (Library Mode)

```go
assertion, sessionKey, err := auth.WebauthnBeginLogin(ctx)
// Send assertion (as JSON) to the browser to call navigator.credentials.get().

// r is the incoming HTTP request whose body is the browser's raw
// navigator.credentials.get() response, forwarded verbatim.
user, tokens, err := auth.WebauthnFinishLogin(ctx, sessionKey, r)
```

### Managing Credentials

```go
creds, err := auth.WebauthnCredentials(ctx, user.ID)
err = auth.WebauthnDeleteCredential(ctx, user, credentialRecordID)
```

### Standalone-service Mode

Both JSON API (Bearer/API-key) and form (cookie session) variants are available, mirroring MFA. The JSON variants return raw tokens; the form variants set auth cookies directly and never expose tokens to client-side JavaScript.

```bash
# Registration (requires the user's own Bearer token):
curl -X POST https://your-host/auth/api/webauthn/register/begin -H "Authorization: Bearer <access-token>" -H "X-API-Key: your-api-key"
# -> pass the "response" fields to navigator.credentials.create() in the browser, then:
curl -X POST "https://your-host/auth/api/webauthn/register/finish?session_key=<key>&name=YubiKey" \
  -H "Authorization: Bearer <access-token>" -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" -d '<navigator.credentials.create() result>'

# Login (no prior auth required):
curl -X POST https://your-host/auth/api/webauthn/login/begin -H "X-API-Key: your-api-key"
# -> pass the "response" fields to navigator.credentials.get() in the browser, then:
curl -X POST "https://your-host/auth/api/webauthn/login/finish?session_key=<key>" -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" -d '<navigator.credentials.get() result>'

# Manage credentials (requires the user's own Bearer token):
curl https://your-host/auth/api/webauthn/credentials -H "Authorization: Bearer <access-token>" -H "X-API-Key: your-api-key"
curl -X DELETE https://your-host/auth/api/webauthn/credentials/<id> -H "Authorization: Bearer <access-token>" -H "X-API-Key: your-api-key"
```

The cookie-mode equivalents live at `/auth/webauthn/register/begin`, `/auth/webauthn/register/finish`, `/auth/webauthn/login/begin`, `/auth/webauthn/login/finish`, `/auth/webauthn/credentials`, and `/auth/webauthn/credentials/{id}` — same request/response shapes, but authenticated via the session cookie (and CSRF token) instead of a Bearer token, and `login/finish` sets auth cookies and returns `{"redirect": "..."}` instead of raw tokens.

## Hooks

ezauth provides a hook system that lets you intercept auth lifecycle events. This is useful for:

- Validating input before user creation (e.g., checking a banned domains table)
- Sending welcome emails or audit logs after registration
- Notifying admins of new user registrations
- Audit logging of sign-ins, sign-outs, and account deletion

### Defining a Hook

Embed `service.DefaultHook` and override only the methods you need:

```go
type MyHook struct {
    service.DefaultHook
    db  *sql.DB
    log *slog.Logger
}

// BeforeUserCreated runs before a new user is persisted.
// Return an error to abort the operation.
func (h MyHook) BeforeUserCreated(ctx context.Context, u *models.User) error {
    var banned bool
    err := h.db.QueryRowContext(ctx,
        "SELECT EXISTS(SELECT 1 FROM banned_domains WHERE domain = ?)",
        emailDomain(u.Email),
    ).Scan(&banned)
    if err != nil {
        return err
    }
    if banned {
        return errors.New("email domain is not allowed")
    }
    return nil
}

// AfterUserCreated runs after a user has been successfully persisted.
func (h MyHook) AfterUserCreated(ctx context.Context, u *models.User) error {
    // Audit log
    _, err := h.db.ExecContext(ctx,
        "INSERT INTO audit_log (event, user_id, ts) VALUES (?, ?, ?)",
        "user.created", u.ID, time.Now(),
    )
    if err != nil {
        return err
    }
    // Send welcome email (async — no extra framework needed)
    go h.sendWelcomeEmail(u.Email)
    h.log.InfoContext(ctx, "new user registered", "id", u.ID, "email", u.Email)
    return nil
}

// AfterUserSignedIn can be used for login notifications or audit trails.
func (h MyHook) AfterUserSignedIn(ctx context.Context, u *models.User) error {
    h.log.InfoContext(ctx, "user signed in", "id", u.ID, "email", u.Email)
    return nil
}
```

### Available Hooks

| Hook                          | Timing                                     | Abortable              |
| ----------------------------- | ------------------------------------------ | ---------------------- |
| `BeforeUserCreated`           | Before creating a new user                 | Yes (return error)     |
| `AfterUserCreated`            | After a new user is persisted              | No (errors are logged) |
| `BeforeUserUpdated`           | Before updating a user                     | Yes (return error)     |
| `AfterUserUpdated`            | After a user is updated                    | No (errors are logged) |
| `BeforeUserDeleted`           | Before deleting a user                     | Yes (return error)     |
| `AfterUserDeleted`            | After a user is deleted                    | No (errors are logged) |
| `AfterUserSignedIn`           | After a successful sign-in                 | No (errors are logged) |
| `AfterUserSignedOut`          | After a successful sign-out                | No (errors are logged) |
| `AfterPasswordResetRequested` | After a password reset is requested        | No (errors are logged) |
| `AfterPasswordResetConfirmed` | After a password reset is confirmed        | No (errors are logged) |
| `AfterOAuth2SignedIn`         | After an existing user signs in via OAuth2 | No (errors are logged) |
| `AfterOAuth2Created`          | After a new user is created via OAuth2     | No (errors are logged) |
| `AfterImpersonationStarted`   | After an admin begins impersonating a user | No (errors are logged) |
| `AfterImpersonationEnded`     | After an impersonation session ends        | No (errors are logged) |
| `AfterMFAEnabled`             | After a user enables TOTP MFA              | No (errors are logged) |
| `AfterMFADisabled`            | After a user disables TOTP MFA             | No (errors are logged) |

### Registering the Hook

```go
auth.SetHook(MyHook{
    db:  sqlDB,
    log: slog.Default(),
})
```

It's safe to call `SetHook` at any point — including after the server is running.

## Swagger Documentation

To generate the Swagger documentation, run:

```bash
make swagger
```

The Swagger UI is available at `/swagger/index.html`.

## Examples

Check out the `_example` directory for ready-to-use examples:

*   [`go-server`](_example/go-server): A complete, plug-and-play example showing how to integrate `ezauth` with a Go web server.
*   [`javascript-client`](_example/javascript-client): An example JavaScript client interacting with the `ezauth` API.
