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

### `RequireAPIKeyScope`

Requires the API key used to authenticate the request (via `APIKeyMiddleware`, which must run upstream) to include the given scope. An unscoped key — including the master config API key, which has no associated `Token` — has full access. See [Scoped API Keys](../guides/account-security.md#scoped-api-keys).

```go
func (h *Handler) RequireAPIKeyScope(scope string) func(http.Handler) http.Handler
```

## Authorization Middleware (RBAC)

See [Roles & Permissions (RBAC)](../guides/admin-operations.md#roles-permissions-rbac) for the full picture — these check the real RBAC tables, not the legacy `User.Roles` string field.

### `RequireRole`

Requires the authenticated user (identified via the request context set by `AuthMiddleware` or `LoadUserMiddleware`/`SessionMiddleware` — must run downstream of one of those) to hold the given role. Returns `401` if no user is in context, `403` if they lack the role.

```go
func (h *Handler) RequireRole(role string) func(http.Handler) http.Handler
```

### `RequirePermission`

Same as `RequireRole`, but checks a permission, resolved transitively through every role granted to the user.

```go
func (h *Handler) RequirePermission(permission string) func(http.Handler) http.Handler
```

## Organization Middleware

### `OrgLoaderMiddleware`

Resolves the "current organization" for a request via an app-supplied `OrgLoader` (`ezauth` doesn't presume how an org is identified — URL param, subdomain, header, etc.) and loads it into context. Mirrors `LoadUserMiddleware` exactly. See [Organizations](../guides/admin-operations.md#organizations).

```go
type OrgLoader func(context.Context) (*models.Organization, error)
func (h *Handler) OrgLoaderMiddleware(loader ezmiddleware.OrgLoader) func(http.Handler) http.Handler
```

## Standalone Middleware Package

Every middleware above is a thin `(h *Handler)` wrapper around a standalone
function in `github.com/josuebrunel/ezauth/pkg/handler/middleware` (imported
as `ezmiddleware` elsewhere in this reference). Reach for the package
directly if you're composing routes without a `Handler` instance — e.g.
protecting a non-`ezauth` route with just a `TokenGetter`/`RoleChecker`
implementation.

```go
// Same logic as the Handler methods above, taking explicit dependencies
// (a RoleChecker, TokenGetter, etc.) instead of a *Handler.
func AuthMiddleware(keyFunc jwt.Keyfunc, validMethods []string) func(http.Handler) http.Handler
func APIKeyMiddleware(configApiKey string, tokenRepo TokenGetter) func(http.Handler) http.Handler
func RequireAPIKeyScope(scope string) func(http.Handler) http.Handler
func RequireRole(checker RoleChecker, role string) func(http.Handler) http.Handler
func RequirePermission(checker PermissionChecker, permission string) func(http.Handler) http.Handler
func LoginRequiredMiddleware(authChecker AuthChecker, loginPath string) func(http.Handler) http.Handler
func LoadUserMiddleware(loader UserLoader) func(http.Handler) http.Handler
func OrgLoaderMiddleware(loader OrgLoader) func(http.Handler) http.Handler
func LoadAndSaveMiddleware(sm *scs.SessionManager) func(http.Handler) http.Handler
func SessionMiddleware(sm *scs.SessionManager, loader UserLoader) func(http.Handler) http.Handler

// Chains middlewares in order: Chain(a, b)(h) runs a, then b, then h.
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler
```

**Context-key constants** — set by the middleware above, read via
`context.Value`: `UserContextKey`, `UserObjectContextKey`,
`ImpersonatorContextKey`, `SessionTokensContextKey`,
`SessionImpersonatorKey`, `APIKeyScopesContextKey`, `OrgContextKey`,
`OrgObjectContextKey`.

**Rate limiting** — the `EZAUTH_RATE_LIMIT_*` settings (see
[Configuration](../configuration.md#rate-limit-settings)) configure the
`RateLimiter` ezauth mounts internally, but you can also run one standalone:

```go
type RateLimitConfig struct {
    Enabled    bool
    Requests   int
    Window     time.Duration
    ByClientIP bool
}

func NewRateLimiter(cfg RateLimitConfig) *RateLimiter
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler
```
