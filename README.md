# ezauth

![CI](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml/badge.svg)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://josuebrunel.github.io/ezauth/)

Simple and easy to use authentication library for Golang.

`ezauth` can be used as a standalone authentication service or embedded directly into your Go application as a library.

## Features

- Email/Password Authentication (Register, Login)
- JWT based sessions (Access & Refresh Tokens, Refresh Token Rotation)
- OAuth2 Support (Google, GitHub, Facebook)
- Password Reset and Passwordless (Magic Link) authentication
- Extended User Profiles (First Name, Last Name, Locale, Timezone, Roles, etc.)
- SQLite and PostgreSQL support
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
   export EZAUTH_DB_DIALECT="sqlite3"
   export EZAUTH_DB_DSN="auth.db"
   export EZAUTH_JWT_SECRET="super-secret-key"

   # SMTP (Optional - for Email features)
   export EZAUTH_SMTP_HOST="smtp.example.com"
   export EZAUTH_SMTP_PORT="587"
   export EZAUTH_SMTP_USER="user@example.com"
   export EZAUTH_SMTP_PASSWORD="password"
   export EZAUTH_SMTP_FROM="noreply@example.com"

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

    // 4. IMPORTANT: Add session middleware so that GetSessionUser works in handlers
    r.Use(auth.Handler.Session.LoadAndSave)

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
tokens, ok := auth.Handler.GetSessionTokens(ctx)
if ok {
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
r.Use(auth.Handler.Session.LoadAndSave)

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

## API Endpoints

### Form-based Handlers (Cookies & Redirects)

These endpoints accept `application/x-www-form-urlencoded`, set secure cookies, and redirect.

| Method | Endpoint                           | Description                 |
| ------ | ---------------------------------- | --------------------------- |
| POST   | `/auth/register`                   | Register a new user         |
| POST   | `/auth/login`                      | Login and set cookies       |
| POST   | `/auth/logout`                     | Clear cookies and logout    |
| POST   | `/auth/password-reset/request`     | Request password reset link |
| POST   | `/auth/password-reset/confirm`     | Confirm password reset      |
| POST   | `/auth/passwordless/request`       | Request magic link          |
| GET    | `/auth/passwordless/login`         | Login via magic link        |
| GET    | `/auth/oauth2/{provider}/login`    | Login via OAuth2 provider   |
| GET    | `/auth/oauth2/{provider}/callback` | OAuth2 provider callback    |

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
