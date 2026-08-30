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
-   `username` (Optional)
-   `first_name` (Optional)
-   `last_name` (Optional)
-   `locale` (Optional)
-   `timezone` (Optional)
-   `phone` (Optional)
-   `avatar_url` (Optional)
-   `nickname` (Optional)
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

### SMS OTP Request (`/auth/sms-otp/request`)
-   `phone` (Required)

### SMS OTP Verify (`/auth/sms-otp/verify`)
-   `phone` (Required)
-   `code` (Required)

### MFA Login Verify (`/auth/mfa/login/verify`)
-   `code` (Required, TOTP or recovery code; the pending `mfa_token` is read from the session, not the form)
-   `remember_device` (Optional; when set, marks the device trusted and sets the trusted-device cookie)

### MFA Confirm (`/auth/mfa/confirm`)
-   `code` (Required, TOTP code from the authenticator app)

### MFA Disable (`/auth/mfa/disable`)
-   `code` (Required, TOTP or recovery code)

The `/auth/webauthn/*` endpoints are not listed here: they take the browser's raw `navigator.credentials` JSON response as the request body (plus `session_key`/`name` query params), not form-encoded fields — see [WebAuthn / Passkeys](#webauthn--passkeys).

## Multi-Factor Authentication (TOTP)

`ezauth` supports TOTP-based MFA (RFC 6238). Once enabled for a user, `CompleteBasicLogin` (used internally by `Login`/`FormLogin`) returns a short-lived `mfa_token` instead of session tokens; the caller exchanges it for a real session via `MFALoginVerify` with a TOTP or recovery code.

```go
// Enrollment (user already authenticated):
enroll, err := auth.MFAEnroll(ctx, user)
// enroll.OTPAuthURL -> render as a QR code; enroll.Secret -> manual entry fallback.

recoveryCodes, err := auth.MFAConfirm(ctx, user, code) // enables MFA

// Step-up login (deviceToken is "" if the caller doesn't support "remember this device"):
loginResp, err := auth.CompleteBasicLogin(ctx, user, deviceToken)
if loginResp.MFARequired {
    user, tokens, newDeviceToken, err := auth.MFALoginVerify(ctx, loginResp.MFAToken, code, rememberDevice)
}

// Disabling:
err = auth.MFADisable(ctx, user, code)
```

For cookie-based (form) clients, `auth.GetMFAEnrollment(ctx)` reads back the pending secret/QR URL stashed in the session by `POST /auth/mfa/enroll`, and `Pages.MFAVerify` (`EZAUTH_MFA_VERIFY_PAGE_URL`) is where `FormLogin` redirects when a step-up is required. `EZAUTH_MFA_ISSUER` sets the issuer name shown in authenticator apps.

### Remember This Device (Trusted Devices)

Passing `rememberDevice=true` to `MFALoginVerify` also issues a trusted-device token; presenting it to `CompleteBasicLogin` on a later login skips MFA step-up entirely until it expires (`EZAUTH_TRUSTED_DEVICE_TTL`, default 30 days).

```go
devices, err := auth.TrustedDevices(ctx, user.ID)
err = auth.RevokeTrustedDevice(ctx, user, devices[0].ID)
```

JSON API clients send the stored device token back via the `X-Device-Token` header on `POST /auth/api/login`. Form/cookie clients get this for free: `FormLogin` reads the trusted-device cookie itself, and `FormMFALoginVerify` sets it (`EZAUTH_TRUSTED_DEVICE_COOKIE_NAME`) when the verification form's `remember_device` field is set.

## WebAuthn / Passkeys

`ezauth` supports WebAuthn/FIDO2 passkey registration and login. Login is **discoverable (usernameless)** — the browser's platform UI lets the user pick a passkey, so no prior email/username is required. WebAuthn is disabled unless `EZAUTH_WEBAUTHN_RP_ID` and `EZAUTH_WEBAUTHN_RP_ORIGINS` are both set, and ceremonies always require client-side JavaScript (`navigator.credentials.create()`/`.get()`) regardless of cookie vs. Bearer auth style.

```go
// Registration (user already authenticated):
creation, sessionKey, err := auth.WebauthnBeginRegistration(ctx, user)
// Send creation as JSON for the browser to call navigator.credentials.create(),
// keep sessionKey for the finish step.

// r's body must be the browser's raw navigator.credentials.create() response.
cred, err := auth.WebauthnFinishRegistration(ctx, user, sessionKey, r, "YubiKey 5")

// Login:
assertion, sessionKey, err := auth.WebauthnBeginLogin(ctx)
// Send assertion as JSON for the browser to call navigator.credentials.get().

// r's body must be the browser's raw navigator.credentials.get() response.
user, tokens, err := auth.WebauthnFinishLogin(ctx, sessionKey, r)

// Managing credentials:
creds, err := auth.WebauthnCredentials(ctx, user.ID)
err = auth.WebauthnDeleteCredential(ctx, user, credentialRecordID)
```

## SMS OTP

`ezauth` supports SMS-based one-time-password login, mirroring the passwordless (magic link) flow but via a 6-digit SMS code. An unrecognized phone number gets a temporary, unverified account, same as an unrecognized email does for passwordless. Requires `EZAUTH_SMS_TWILIO_ACCOUNT_SID`/`_AUTH_TOKEN`/`_FROM`; falls back to a mock sender otherwise. Phone numbers are enforced unique at the database level.

```go
err := auth.Service.SMSOTPRequest(ctx, service.RequestSMSOTP{Phone: "+15551234567"})

tokens, err := auth.Service.SMSOTPVerify(ctx, service.RequestSMSOTPVerify{
    Phone: "+15551234567",
    Code:  "123456",
})
```

`EZAUTH_SMS_OTP_BODY` customizes the SMS message template (`{{.Code}}`, `{{.Phone}}` available).

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

## Using an Existing Database Connection


If your application already has a `*sql.DB` connection, you can use `NewWithDB`:

```go
auth, err := ezauth.NewWithDB(&cfg, myDBConnection, "auth")
```
