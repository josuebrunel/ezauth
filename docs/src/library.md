# Using ezauth as a Library

Embedding `ezauth` directly into your Go application provides the most seamless integration. It allows you to use `ezauth`'s middleware and internal services directly within your code.

## Basic Integration

Here is a complete example of how to integrate `ezauth` into a `chi` router, ensuring the session middleware is correctly configured:

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
    // ... set other necessary env vars

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

    // Public Route (Login)
    r.Get("/signin", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Login Page"))
    })

    // Protected Route
    r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        // Retrieve the authenticated user
        user, err := auth.GetSessionUser(r.Context())

        if err != nil {
            http.Redirect(w, r, "/signin", http.StatusSeeOther)
            return
        }

        w.Write([]byte(fmt.Sprintf("Welcome, %s!", user.Email)))
    })

    fmt.Println("Server starting on :3000")
    http.ListenAndServe(":3000", r)
}
```

## Retrieving Authenticated User

To retrieve the authenticated user from the session cookies, you **must** mount the session middleware.

```go
// 1. Mount session middleware (Required for GetSessionUser)
r.Use(auth.Handler.Session.LoadAndSave)

// 2. Access the user in your handler
r.Get("/", func(w http.ResponseWriter, r *http.Request) {
    user, err := auth.GetSessionUser(r.Context())
    if err != nil {
        // User is not authenticated or session expired
        return
    }
    // Access user fields
    fmt.Println(user.Email)
})
```

### Optimizing with Middleware

If you use `GetSessionUser` frequently, you can use the `LoadUserMiddleware` to pre-load the user into the context. This avoids repeated DB lookups if multiple handlers/middlewares need the user info in the same request.

```go
r.Use(auth.LoadUserMiddleware)

r.Get("/", func(w http.ResponseWriter, r *http.Request) {
    // This will be fast as it retrieves from context
    user, err := auth.GetSessionUser(r.Context())
    // ...
})
```

## Handling Flash Messages

Form-based handlers use flash messages for errors and success notifications. Flash messages are stored in the session and are automatically cleared after being read (one-time display).

```go
r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
    // Get and clear any error flash message
    if errMsg := auth.GetErrorMessage(r.Context()); errMsg != "" {
        // Display error to user (e.g., "invalid credentials")
    }

    // Get and clear any success flash message  
    if successMsg := auth.GetSuccessMessage(r.Context()); successMsg != "" {
        // Display success to user (e.g., "password reset link sent")
    }

    // Render login page...
})
```

> [!NOTE]
> Flash messages are set automatically by the form handlers (e.g., `FormLogin`, `FormRegister`) when errors occur or actions succeed. You just need to retrieve and display them in your page handlers.

## Core Components

When you initialize `ezauth`, you get access to several key components through the `EzAuth` struct:

### `EzAuth` Struct

The `EzAuth` struct is the main entry point. It contains:
- `Config`: The loaded configuration.
- `Repo`: The database repository.
- `Service`: The core authentication logic.
- `Handler`: The HTTP handler.

### The Handler

The `Handler` (accessible via `auth.Handler`) handles all HTTP routing and request processing. It is built on top of `chi`, but it implements the `http.Handler` interface, so it can be used with any Go HTTP framework.

Key methods:
- `ServeHTTP(w, r)`: Standard HTTP handler method.
- `AuthMiddleware(next)`: Middleware to protect routes. It validates the JWT in the `Authorization` header and puts the `userID` in the request context.

### The Service

The `Service` (accessible via `auth.Service`) contains the business logic for authentication. You can use it directly if you want to perform actions programmatically without going through HTTP.

Example of using the service directly:

```go
// Create a user manually
user, err := auth.Service.UserCreate(ctx, &service.RequestBasicAuth{
    Email: "user@example.com",
    Password: "securepassword",
})

// Generate tokens for a user
tokens, err := auth.Service.TokenCreate(ctx, user)
```



## Form Field Reference

When using the form-based endpoints (e.g., `/auth/register`, `/auth/login`), `ezauth` expects the following form fields in the POST request body (`application/x-www-form-urlencoded`):

### Registration (`/auth/register`)
-   `email` (Required)
-   `password` (Required, min 8 chars)
-   `password_confirm` (Required)
-   `first_name` (Optional)
-   `last_name` (Optional)
-   `locale` (Optional)
-   `timezone` (Optional)
-   `roles` (Optional, comma-separated)
-   `meta_` (Optional)
    -   Any field starting with `meta_` will be added to the user's metadata (e.g., `meta_theme=dark` -> user_metadata: `{ "theme": "dark" }`).

### Login (`/auth/login`)
-   `email` (Required)
-   `password` (Required)

### Password Reset Request (`/auth/password-reset/request`)
-   `email` (Required)

### Password Reset Confirm (`/auth/password-reset/confirm`)
-   `token` (Required, usually passed via hidden input or query param)
-   `password` (Required, the new password)

### Magic Link Request (`/auth/passwordless/request`)
-   `email` (Required)

### Magic Link Login (`/auth/passwordless/login`)
-   `token` (Required, passed as a query parameter: `?token=...`)

## Using an Existing Database Connection


If your application already has a `*sql.DB` connection, you can use `NewWithDB`:

```go
auth, err := ezauth.NewWithDB(&cfg, myDBConnection, "auth")
```
