# ezauth

[![Tests](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml/badge.svg)](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://josuebrunel.github.io/ezauth/)
[![Go Reference](https://pkg.go.dev/badge/github.com/josuebrunel/ezauth.svg)](https://pkg.go.dev/github.com/josuebrunel/ezauth)

Simple and easy to use authentication library for Golang.

`ezauth` can be used as a standalone authentication service or embedded directly into your Go application as a library.

## Features

- Email/Password Authentication (Register, Login)
- JWT based sessions (Access & Refresh Tokens, Refresh Token Rotation)
- OAuth2 Support (Google, GitHub, Facebook)
- Password Reset and Passwordless (Magic Link) authentication
- Extended User Profiles (First Name, Last Name, Locale, Timezone, Roles, etc.)
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

When using the form-based handlers (e.g., `POST /auth/login`), `ezauth` automatically enforces CSRF protection using `filippo.io/csrf/gorilla` and your `EZAUTH_JWT_SECRET`. 

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

- `HasRole(role string) bool`: Checks if the user has a specific role.
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
| POST   | `/auth/password-reset/request`     | Request password reset link                                                 |
| POST   | `/auth/password-reset/confirm`     | Confirm password reset                                                      |
| POST   | `/auth/passwordless/request`       | Request magic link                                                          |
| GET    | `/auth/passwordless/login`         | Login via magic link                                                        |
| GET    | `/auth/oauth2/{provider}/login`    | Login via OAuth2 provider                                                   |
| GET    | `/auth/oauth2/{provider}/callback` | OAuth2 provider callback. URL: `{base_url}/auth/oauth2/{provider}/callback` |

#### Form Field Reference

| Endpoint                       | Required Fields                         | Optional Fields                                                    |
| :----------------------------- | :-------------------------------------- | :----------------------------------------------------------------- |
| `/auth/register`               | `email`, `password`, `password_confirm` | `first_name`, `last_name`, `locale`, `timezone`, `roles`, `meta_*` |
| `/auth/login`                  | `email`, `password`                     |                                                                    |
| `/auth/password-reset/request` | `email`                                 |                                                                    |
| `/auth/password-reset/confirm` | `token`, `password`                     |                                                                    |
| `/auth/passwordless/request`   | `email`                                 |                                                                    |
| `/auth/passwordless/login`     | `token` (query param)                   |                                                                    |

> [!NOTE]
> Passwords must be at least 8 characters long.

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
| DELETE | `/auth/api/user`                   | Delete account (Protected)        |

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
