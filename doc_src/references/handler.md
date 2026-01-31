# Handler Reference

The `Handler` struct is responsible for handling all HTTP requests for `ezauth`. It uses `chi` for routing.

```go
type Handler struct {
    // contains filtered or unexported fields
	Session *scs.SessionManager
}
```

## Constructor

### `New`

Creates a new `Handler` instance.

```go
func New(svc *service.Auth, path string, options ...HandlerOption) *Handler
```

- **svc**: The `service.Auth` instance.
- **path**: The base path for the auth routes (e.g., "/auth").
- **options**: Functional options for configuration.

## Methods

### `Run`

Starts the HTTP server on the address configured in `service.Config`.

```go
func (h *Handler) Run()
```

### `ServeHTTP`

Implements the `http.Handler` interface, allowing the `Handler` to be mounted on any Go HTTP router.

```go
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

### `LoadUserMiddleware`

Middleware that loads the authenticated user into the request context. This is required if you want to use `GetSessionUser(ctx)` in downstream handlers without reference to the `Handler` instance.

```go
func (h *Handler) LoadUserMiddleware(next http.Handler) http.Handler
```

### `GetSessionUser`

Retrieves the authenticated user. It checks:

1.  Context (if `LoadUserMiddleware` was used)
2.  Session Cookies (extracts tokens and verifies with DB)

```go
func (h *Handler) GetSessionUser(ctx context.Context) (*models.User, error)
```

### `IsAuthenticated`

Checks if the request is authenticated. It returns `true` if a user can be retrieved from the context or session.

```go
func (h *Handler) IsAuthenticated(ctx context.Context) bool
```

## HTTP Handlers

The following methods are attached to routes internally by `New`, but are public if you need to wrap or mock them.

### Auth
-   `Login(w, r)`: JSON Login
-   `Register(w, r)`: JSON Register
-   `Logout(w, r)`: User logout
-   `RefreshToken(w, r)`: Refresh access token
-   `OAuth2Login(w, r)`: Initiate OAuth2 flow
-   `OAuth2Callback(w, r)`: OAuth2 callback handler

### User Management
-   `UserInfo(w, r)`: Get current user info
-   `DeleteUser(w, r)`: Delete current user account

### Password Management
-   `PasswordResetRequest(w, r)`: Request password reset link
-   `PasswordResetConfirm(w, r)`: Confirm password reset
-   `PasswordlessRequest(w, r)`: Request magic link
-   `PasswordlessLogin(w, r)`: Login via magic link

### Form Handlers
These handlers process `application/x-www-form-urlencoded` requests and return HTML redirects.

-   `FormLogin(w, r)`
-   `FormRegister(w, r)` (Supports `password_confirm` and `meta_` fields)
-   `FormLogout(w, r)`
-   `FormPasswordResetRequest(w, r)`
-   `FormPasswordResetConfirm(w, r)`
-   `FormPasswordlessRequest(w, r)`
-   `FormPasswordlessLogin(w, r)`
