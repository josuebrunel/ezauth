# Using ezauth as a Library

Embedding `ezauth` directly into your Go application provides the most seamless integration. It allows you to use `ezauth`'s middleware and internal services directly within your code.

## Basic Integration

Here is a complete example of how to integrate `ezauth` into a `chi` router:

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
    // LoadConfig reads from environment variables with the EZAUTH_ prefix.
    cfg, err := config.LoadConfig()
    if err != nil {
        panic(err)
    }

    // 2. Initialize EzAuth
    // "auth" is the path prefix where the routes will be mounted.
    auth, err := ezauth.New(&cfg, "auth")
    if err != nil {
        panic(err)
    }

    // 3. Run migrations
    // Ensure the database schema is up to date.
    if err := auth.Migrate(); err != nil {
        panic(err)
    }

    r := chi.NewRouter()

    // 4. Mount Auth Routes
    // This exposes /auth/register, /auth/login, etc.
    // auth.Handler implements http.Handler.
    r.Mount("/auth", auth.Handler)

    // 5. Protect your own routes
    r.Group(func(r chi.Router) {
        r.Use(auth.AuthMiddleware)

        r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
            // Retrieve the userID from the context
            userID, _ := auth.GetUserID(r.Context())
            w.Write([]byte("Hello user: " + userID))
        })
    })

    http.ListenAndServe(":3000", r)
}
```

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

## Using an Existing Database Connection

If your application already has a `*sql.DB` connection, you can use `NewWithDB`:

```go
auth, err := ezauth.NewWithDB(&cfg, myDBConnection, "auth")
```
