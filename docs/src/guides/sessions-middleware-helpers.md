# Sessions, Middleware and Helpers

The core building blocks for form-based (cookie) auth: managing the session, retrieving the authenticated user, surfacing flash messages, CSRF protection, the route-protection middlewares, and the package-level helper functions for handlers and templates.

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

## Helper Functions

`ezauth` provides package-level helper functions for convenient access to authentication context. These can be used in your handlers or templates.

> [!IMPORTANT]
> Middleware prerequisites vary per helper: `SessionMiddleware` populates the session/cookie-based helpers (`GetUser`, `GetSessionTokens`, cookie-mode impersonation) and `AuthMiddleware` the JWT/Bearer ones (`GetUserID`, `GetImpersonatorID`). `GetUserID`, `GetUser`, and `IsAuthenticated` work under any of `SessionMiddleware`, `LoadUserMiddleware`, or `AuthMiddleware`.

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

    // Get the session's access/refresh tokens (requires SessionMiddleware)
    tokens, err := ezauth.GetSessionTokens(r.Context())
    if err == nil {
        accessToken := tokens["access_token"] // ...
    }

    // Detect an impersonation session, regardless of transport
    // (cookie session or Bearer/JWT "act" claim)
    if adminID, ok := ezauth.CurrentImpersonatorID(r.Context()); ok {
        // acting as another user on behalf of adminID
    }
}
```

### User Model Helpers

When you have a `models.User` object, you can use these helper methods:

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
- `GetMeta[T any](user, key) (T, bool)`: Retrieves a value from `UserMetadata`.
- `SetMeta(key, value)`: Sets a value in `UserMetadata`.
- `GetAppMeta[T any](user, key) (T, bool)`: Retrieves a value from `AppMetadata`.
- `SetAppMeta(key, value)`: Sets a value in `AppMetadata`.
