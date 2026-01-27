# ezauth

![CI](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml/badge.svg)

Simple and easy to use authentication library for Golang.

`ezauth` can be used as a standalone authentication service or embedded directly into your Go application as a library.

## Features

- Email/Password Authentication (Register, Login)
- JWT based sessions (Access & Refresh Tokens)
- OAuth2 Support (Google, GitHub, Facebook)
- SQLite and PostgreSQL support
- Built-in Middleware for route protection

## Usage

### As a Standalone Service

You can run `ezauth` as a separate service that handles authentication for your microservices.

1. **Configuration**: Set environment variables.
   ```bash
   export EZAUTH_ADDR=":8080"
   export EZAUTH_DB_DIALECT="sqlite3"
   export EZAUTH_DB_DSN="auth.db"
   export EZAUTH_JWT_SECRET="super-secret-key"

   # OAuth2 (Optional)
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

Embed `ezauth` directly into your existing Go application (e.g., using `chi`).

```go
package main

import (
    "net/http"
    "github.com/go-chi/chi/v5"
    "github.com/josuebrunel/ezauth/pkg/config"
    "github.com/josuebrunel/ezauth/pkg/handler"
    "github.com/josuebrunel/ezauth/pkg/service"
)

func main() {
    // 1. Setup Config
    cfg := &config.Config{
        DB: config.Database{
            Dialect: "sqlite3",
            DSN:     "file:auth.db?cache=shared&mode=rwc",
        },
        JWTSecret: "your-secret",
    }

    // 2. Initialize Service and Handler
    authSvc := service.New(cfg)
    // Pass empty string as path if you are mounting it with a prefix in your router
    authHandler := handler.New(authSvc, "") 

    r := chi.NewRouter()

    // 3. Mount Auth Routes
    // This exposes /auth/register, /auth/login, /auth/token/refresh, etc.
    r.Mount("/auth", authHandler)

    // 4. Protect your own routes
    r.Group(func(r chi.Router) {
        r.Use(authHandler.AuthMiddleware)

        r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
            userID, _ := handler.GetUserID(r.Context())
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
| GET    | `/auth/userinfo`                   | Get current user info (Protected) |
| POST   | `/auth/logout`                     | Revoke refresh token (Protected)  |
| DELETE | `/auth/user`                       | Delete account (Protected)        |
| GET    | `/auth/oauth2/{provider}/login`    | Login via OAuth2 provider         |
| GET    | `/auth/oauth2/{provider}/callback` | OAuth2 provider callback          |
