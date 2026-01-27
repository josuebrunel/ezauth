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
- Built-in Middleware for route protection
- Swagger API Documentation

## Usage

### As a Standalone Service

You can run `ezauth` as a separate service that handles authentication for your microservices.

1. **Configuration**: Set environment variables.
   ```bash
   export EZAUTH_ADDR=":8080"
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
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/josuebrunel/ezauth"
    "github.com/josuebrunel/ezauth/pkg/config"
)

func main() {
    // 1. Setup Config
    cfg, err := config.LoadConfig()
    if err != nil {
        panic(err)
    }

    // 2. Initialize EzAuth
    // The second argument is the path prefix for the auth routes.
    // You can also use ezauth.NewWithDB(&cfg, db, "auth") if you have an existing *sql.DB connection.
    auth, err := ezauth.New(&cfg, "auth")
    if err != nil {
        panic(err)
    }

    // 3. Run migrations
    if err := auth.Migrate(); err != nil {
        panic(err)
    }

    r := chi.NewRouter()

    // 4. Mount Auth Routes
    // This exposes /auth/register, /auth/login, /auth/token/refresh, etc.
    r.Mount("/auth", auth.Handler)

    // 5. Protect your own routes
    r.Group(func(r chi.Router) {
        r.Use(auth.AuthMiddleware)

        r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
            userID, _ := auth.GetUserID(r.Context())
            w.Write([]byte("Hello user: " + userID))
        })
    })

    http.ListenAndServe(":3000", r)
}
```

## API Endpoints

| Method | Endpoint                           | Description                       |
| ------ | ---------------------------------- | --------------------------------- |
| POST   | `/auth/register`                   | Register a new user               |
| POST   | `/auth/login`                      | Login and receive tokens          |
| POST   | `/auth/token/refresh`              | Refresh access token              |
| POST   | `/auth/password-reset/request`     | Request password reset link       |
| POST   | `/auth/password-reset/confirm`     | Confirm password reset            |
| POST   | `/auth/passwordless/request`       | Request magic link                |
| GET    | `/auth/passwordless/login`         | Login via magic link              |
| GET    | `/auth/userinfo`                   | Get current user info (Protected) |
| POST   | `/auth/logout`                     | Revoke refresh token (Protected)  |
| DELETE | `/auth/user`                       | Delete account (Protected)        |
| GET    | `/auth/oauth2/{provider}/login`    | Login via OAuth2 provider         |
| GET    | `/auth/oauth2/{provider}/callback` | OAuth2 provider callback          |

## Swagger Documentation

To generate the Swagger documentation, run:

```bash
make swagger
```

The Swagger UI is available at `/swagger/index.html`.
