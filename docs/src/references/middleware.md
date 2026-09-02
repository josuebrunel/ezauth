# Middleware Reference

`ezauth` provides several middlewares to handle authentication and authorization.

## Core Middleware

### `LoginRequiredMiddleware`

Checks if a user is authenticated. This middleware is "content-aware":

-   **Browser Request**: Redirects to the configured Login Page.
-   **API Request** (`/api/*` or `Accept: application/json`): Returns `401 Unauthorized`.

```go
func (h *Handler) LoginRequiredMiddleware(next http.Handler) http.Handler
```

**Usage:**

```go
r.Group(func(r chi.Router) {
    r.Use(auth.LoginRequiredMiddleware)
    r.Get("/dashboard", dashboardHandler)
})
```

### `SessionMiddleware`

Manages the cookie-based session (via `scs`) and loads the authenticated user into the request context for Form-based (non-API) routes. Must be mounted on the router for `GetSessionUser`, `GetSessionTokens`, `IsAuthenticated`, and flash-message helpers to work.

```go
func (h *Handler) SessionMiddleware(next http.Handler) http.Handler
```

**Usage:**

```go
r.Use(auth.SessionMiddleware)
```

### `LoadUserMiddleware`

Loads the authenticated user into the request context from a Bearer token or API key, without requiring the cookie-based session. This allows downstream handlers to use `auth.GetSessionUser(ctx)` without needing access to the `Handler` instance. This is useful if you want to use `ezauth`'s user data in your own handlers that are not part of the `auth` package logic.

```go
func (h *Handler) LoadUserMiddleware(next http.Handler) http.Handler
```

## JSON API Middleware

### `AuthMiddleware` (Bearer)

Validates the `Authorization: Bearer <token>` header. It parses the JWT, verifies the signature against the configured signing key (`EZAUTH_JWT_SECRET` for the default HS256 mode, or the asymmetric key(s) under `EZAUTH_JWT_*` — see [Asymmetric JWT Signing (JWKS)](../guides/account-security.md#asymmetric-jwt-signing-jwks)), and sets the user ID in the context.

```go
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler
```

### `APIKeyMiddleware`

Validates the `X-API-Key` header. It checks against the configured Master API Key or looks up an API Key token in the database.

```go
func (h *Handler) APIKeyMiddleware(next http.Handler) http.Handler
```
