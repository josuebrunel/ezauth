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

    // 4. Add session middleware (handles sessions and user loading)
    r.Use(auth.SessionMiddleware)

    // 5. Hooks (Optional - react to auth events)
    auth.Hooks.OnUserCreated = func(ctx context.Context, user *ezauth.User) error {
        fmt.Printf("Welcome email sent to %s\n", user.Email)
        return nil
    }

    // 6. Mount Auth Routes
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

## Helper Functions

`ezauth` provides package-level helper functions for convenient access to authentication context. These can be used in your handlers or templates.

> [!IMPORTANT]
> These functions require the appropriate middleware (`SessionMiddleware`, `LoadUserMiddleware`, or `AuthMiddleware`) to be mounted on the router path.

```go
import "github.com/josuebrunel/ezauth"

func MyHandler(w http.ResponseWriter, r *http.Request) {
    // Check if authenticated (checks both User object and UserID in context)
    if ezauth.IsAuthenticated(r.Context()) {
        // ...
    }

    // Get User ID (works with both Session and JWT auth)
    userID, err := ezauth.GetUserID(r.Context())
    if err != nil {
        // Handle error (e.g. user not found in context)
    }

    // Get User Object (requires LoadUserMiddleware or SessionMiddleware)
    user, err := ezauth.GetUser(r.Context())
    if err != nil {
        // Handle error
    } else {
        fmt.Println("User email:", user.Email)

        // Check Role
        if user.HasRole("admin") {
            // ...
        }

        // Get Metadata (generic)
        if theme, ok := models.GetMeta[string](user, "theme"); ok {
            // ...
        }
    }
}
```

### User Model Helpers

When you have a `models.User` object, you can use these helper methods:

- `HasRole(role string) bool`: Checks if the user has a specific role.
- `GetMeta[T any](user, key) (T, bool)`: Retrieves a value from `UserMetadata`.
- `SetMeta(key, value)`: Sets a value in `UserMetadata`.
- `GetAppMeta[T any](user, key) (T, bool)`: Retrieves a value from `AppMetadata`.
- `SetAppMeta(key, value)`: Sets a value in `AppMetadata`.

## Retrieving Authenticated User

To retrieve the authenticated user from the session cookies, you **must** mount the session middleware.

```go
// 1. Mount session middleware
r.Use(auth.SessionMiddleware)

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
 
 The `auth.SessionMiddleware` already includes user loading, so `GetSessionUser` will be fast (context retrieval).
 
 If you are **not** using `SessionMiddleware` but still want to pre-load the user (e.g. if you handle sessions manually), you can use `LoadUserMiddleware`:
 
 ```go
 r.Use(auth.Handler.Session.LoadAndSave) // Session only
 r.Use(auth.LoadUserMiddleware)          // Pre-load user
 
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
 
### CSRF Protection

When using the form-based handlers (e.g., `POST /auth/login`), `ezauth` automatically enforces Cross-Site Request Forgery (CSRF) protection using `filippo.io/csrf/gorilla`. The protection uses your configured `EZAUTH_JWT_SECRET` as the key.

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
> JSON API endpoints (`/auth/api/*`) do not require CSRF tokens since they utilize JWT Bearer authentication instead of cookie-based sessions.

 ## Middlewares
 
 `ezauth` comes with "plug and play" middlewares to help you secure your application. These are exposed via the `EzAuth` struct (e.g., `auth.SessionMiddleware`).
 
 | Middleware                | Description                                                                                                                               | Usage                                 |
 | :------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------ |
 | `SessionMiddleware`       | **Recommended**. Manages sessions (cookies) AND loads the authenticated user into context. Use this if you want `GetSessionUser` to work. | `r.Use(auth.SessionMiddleware)`       |
 | `LoginRequiredMiddleware` | Restricts access to authenticated users only. Redirects to login page (browser) or returns 401 (API).                                     | `r.Use(auth.LoginRequiredMiddleware)` |
 | `LoadUserMiddleware`      | Loads the user into context. Use this if you are handling sessions manually or want to optimize repeated user lookups.                    | `r.Use(auth.LoadUserMiddleware)`      |
 | `AuthMiddleware`          | Protects API endpoints using JWT Bearer tokens (`Authorization: Bearer <token>`).                                                         | `r.Use(auth.AuthMiddleware)`          |
 
 ### Example: Protecting a Dashboard
 
 ```go
 // 1. Setup Session (at the router root level)
 r.Use(auth.SessionMiddleware)
 
 // 2. Protect specific routes
 r.Group(func(r chi.Router) {
     r.Use(auth.LoginRequiredMiddleware)
     
     r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
         // User is guaranteed to be authenticated here
         user, _ := auth.GetSessionUser(r.Context())
         w.Write([]byte("Hello " + user.Email))
     })
 })
 ```
 
## Hooks

`ezauth` includes a lightweight hook system that allows you to plug in custom logic at key points in the authentication lifecycle (e.g., sending a welcome email, auditing sign-ins, or syncing users to external services).

Hooks are available on the `EzAuth.Hooks` struct as function fields. All hooks are `nil` by default and are called synchronously.

```go
auth.Hooks.OnUserCreated = func(ctx context.Context, user *ezauth.User) error {
    // Send welcome email, setup profile, etc.
    return nil
}

auth.Hooks.OnOAuth2SignedIn = func(ctx context.Context, user *ezauth.User, provider string) error {
    log.Printf("User %s signed in via %s", user.Email, provider)
    return nil
}
```

### Supported Hooks

| Hook                       | Description                                         |
| -------------------------- | --------------------------------------------------- |
| `OnUserCreated`            | Called when a new user is registered (Email or API) |
| `OnUserUpdated`            | Called when user info or password is changed        |
| `OnUserDeleted`            | Called when a user account is deleted               |
| `OnUserSignedIn`           | Called after a successful login (Email/Password)    |
| `OnUserSignedOut`          | Called after a successful logout                    |
| `OnUserTokenRefreshed`     | Called after a successful token refresh             |
| `OnPasswordResetRequested` | Called when a password reset link is sent           |
| `OnPasswordResetConfirmed` | Called after a successful password reset            |
| `OnPasswordlessRequested`  | Called when a magic link is sent                    |
| `OnPasswordlessSignedIn`   | Called after a successful magic link login          |
| `OnOAuth2SignedIn`         | Called after any successful OAuth2 login            |
| `OnOAuth2Created`          | Called when a new user is created via OAuth2        |

 ## Core Components

When you initialize `ezauth`, you get access to several key components through the `EzAuth` struct:

### `EzAuth` Struct

The `EzAuth` struct is the main entry point. It contains:
- `Config`: The loaded configuration.
- `Repo`: The database repository.
- `Service`: The core authentication logic.
- `Handler`: The HTTP handler.
- `Hooks`: The hook system.

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
