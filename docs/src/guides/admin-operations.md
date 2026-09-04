# Admin and Operations

Admin-facing features: impersonation, invitation-based onboarding, user management, the persisted audit log, and the hook system.

> [!WARNING]
> These features enforce no role checks themselves — your application must verify the caller is allowed (e.g. `caller.HasRole("admin")`) before exposing them.

## Impersonation

`ezauth` supports admin impersonation: an authenticated user can act as another user (e.g. for customer support debugging), then swap back to their own session.

> [!IMPORTANT]
> `ezauth` enforces **no authorization** for who may impersonate (same stance as [Invitation-Based Onboarding](#invitation-based-onboarding) and [Admin User Management](#admin-user-management)). The `Impersonate` method mints tokens for any target user on behalf of whoever calls it — check `adminUser.HasRole("admin")` (or equivalent) yourself before calling it.

```go
// adminUser must already be authenticated; check authorization yourself first.
if !adminUser.HasRole("admin") {
    // reject
}

tokenResp, err := auth.Service.Impersonate(ctx, adminUser, targetUserID)
// tokenResp.AccessToken / tokenResp.RefreshToken now authenticate as targetUser,
// with the access token carrying an "act" claim identifying adminUser.

// ... later, end the impersonation session:
err = auth.Service.StopImpersonating(ctx, tokenResp.RefreshToken)
```

Detecting whether the current request is an impersonation session depends on which auth mode the route uses:

```go
// Bearer/JWT mode (requires AuthMiddleware): reads the "act" claim.
impersonatorID, err := ezauth.GetImpersonatorID(ctx)

// Cookie/session mode: reads the swapped-in session data.
adminID, isImpersonating := auth.IsImpersonating(ctx)
if isImpersonating {
    admin, _ := auth.GetImpersonator(ctx) // full *models.User for adminID
    fmt.Println("acting as admin:", admin.Email)
}
```

These two are backed by different mechanisms (JWT claims vs. session storage), so a route reachable over either transport would otherwise need to branch on which one applies. For that case, use the transport-agnostic pair instead — they check both and return whichever applies:

```go
adminID, ok := auth.CurrentImpersonatorID(ctx) // (string, bool)
admin, err := auth.CurrentImpersonator(ctx)     // (*models.User, error)
```

Safe to call regardless of transport: the session-manager middleware always runs first, even on Bearer-only routes, so the cookie-mode check never panics for lack of loaded session data — it just finds nothing and falls through to the JWT check.

See the [Impersonation section of the README](https://github.com/josuebrunel/ezauth#impersonation) for the standalone-service (JSON API / form) equivalents.

## Roles & Permissions (RBAC)

`ezauth` also has real RBAC: `roles`/`permissions` tables (many-to-many, via `role_permissions`/`user_roles` join tables) plus `RequireRole`/`RequirePermission` middleware that enforce against them. This is a fully separate, additive system from the legacy comma-separated `User.Roles` field and its `HasRole`/`AddRole`/`RemoveRole`/etc. helpers — those keep working exactly as before, but `RequireRole`/`RequirePermission` consult the RBAC tables, not that field. Use whichever fits: the string field for a quick, ungoverned tag on a user; the tables when you need actual enforcement, an audit trail of grants/revokes, or permissions distinct from roles.

```go
// One-time setup: define roles/permissions and wire them together.
role, _ := auth.Service.RoleCreate(ctx, "editor", "can edit content")
perm, _ := auth.Service.PermissionCreate(ctx, "posts:write", "write posts")
_ = auth.Service.RolePermissionGrant(ctx, "editor", "posts:write")

// Grant/revoke a role on a user — idempotent, and records an
// AuditEventRoleGranted/AuditEventRoleRevoked audit event (see Audit Log below).
_ = auth.Service.UserRoleGrant(ctx, user.ID, "editor")
_ = auth.Service.UserRoleRevoke(ctx, user.ID, "editor")

// Check directly, or gate a route with the middleware.
has, _ := auth.Service.UserHasRole(ctx, user.ID, "editor")
has, _ = auth.Service.UserHasPermission(ctx, user.ID, "posts:write") // resolved transitively through the user's roles

router.Handle("/admin/posts", auth.RequireRole("editor")(postsHandler))
router.Handle("/admin/posts", auth.RequirePermission("posts:write")(postsHandler))
```

`RequireRole`/`RequirePermission` read the authenticated user ID from request context (set by `AuthMiddleware` or `LoadUserMiddleware`/`SessionMiddleware`), so they must run downstream of one of those; a missing user returns 401, a missing role/permission returns 403. Deleting a role or permission cascades: matching `user_roles`/`role_permissions` assignment rows are removed automatically.

## Organizations

Lightweight multi-tenancy: organizations/teams, with each member holding one role per organization — drawn from the same RBAC role catalog `RequireRole` checks against (a role is just an `ezauth_roles` row; org membership is `ezauth_org_members`, mapping `(org, user) → role`). Kept deliberately minimal — no settings/billing/invitations — a consuming app that needs more can extend via its own table FK'd to `ezauth_organizations`.

```go
org, err := auth.Service.OrganizationCreate(ctx, "Acme Inc")

// OrgMemberAdd upserts: calling it again for the same (org, user) updates the role.
err = auth.Service.OrgMemberAdd(ctx, org.ID, user.ID, "editor")
err = auth.Service.OrgMemberRemove(ctx, org.ID, user.ID)

members, err := auth.Service.OrgMembersList(ctx, org.ID)          // []*models.OrgMember, RoleName joined in
orgs, err := auth.Service.UserOrganizationsList(ctx, user.ID)      // organizations this user belongs to
```

**Resolving the "current org" for a request** mirrors how `LoadUserMiddleware`/`GetSessionUser` resolve the current user — `ezauth` doesn't presume how an org is identified (URL param, subdomain, header, etc.), so you supply an `OrgLoader`:

```go
r.Use(auth.OrgLoaderMiddleware(func(ctx context.Context) (*models.Organization, error) {
    orgID := chi.URLParam(r, "orgID") // or a subdomain, header, etc. — your choice
    return auth.Service.OrganizationGetByID(ctx, orgID)
}))
```

```go
org, err := auth.GetSessionOrg(ctx) // *models.Organization, set by OrgLoaderMiddleware
```

There's no `RequireOrgRole` middleware — compose `OrgLoaderMiddleware` with `RequireRole`/`RequirePermission` if a route needs to enforce the current org member's role.

## Invitation-Based Onboarding

An existing user invites someone by email; the invitee gets a link that pre-fills registration with their email pre-verified and, optionally, a pre-assigned role. `ezauth` enforces no authorization on who may invite (same stance as `Impersonate`) — check that yourself before calling it. `Roles` and `Data` are opaque to `ezauth` beyond being carried through to the created account.

```go
info, err := auth.Service.InvitationCreate(ctx, inviter, service.RequestInvitation{
    Email: "newperson@example.com",
    Roles: "member",
    Data:  map[string]any{"org_id": "org-123"},
})

// The invitee later submits a password from the emailed link:
user, tokens, err := auth.Service.InvitationAccept(ctx, service.RequestInvitationAccept{
    Token:    tokenFromLink,
    Password: "their-chosen-password",
})

invitations, err := auth.Service.Invitations(ctx, inviter.ID)
err = auth.Service.InvitationRevoke(ctx, inviter, invitations[0].ID)
```

`EZAUTH_INVITATION_TTL` (default 7 days) controls how long an invitation stays valid. `EZAUTH_INVITATION_ACCEPT_PAGE_URL` (`Pages.InvitationAccept`) is where `GET /auth/invitation/accept?token=...` redirects, with the token preserved as a query param.

## Admin User Management

Beyond impersonation, `ezauth` exposes admin-facing methods to list/search/filter users, suspend/reactivate an account, and view a user's auth history. `ezauth` enforces no authorization on who may call these (same stance as `Impersonate`) — check that yourself before exposing them.

```go
result, err := auth.Service.UsersList(ctx, service.ListUsersOptions{
    Search: "alice",
    Status: models.UserStatusSuspended, // "active" | "locked" | "suspended"
    Limit:  20,
})
// result.Users (PasswordHash stripped), result.HasMore

user, err := auth.Service.UserSuspend(ctx, targetUserID)
user, err = auth.Service.UserReactivate(ctx, targetUserID)

history, err := auth.Service.UserAuthHistory(ctx, targetUserID, 50)
```

`ListUsersOptions` also supports `CreatedAfter`/`CreatedBefore` and `LastActiveAfter`/`LastActiveBefore` (`*time.Time`) for date-range filtering. `UserStatusActive`/`Locked`/`Suspended` are derived from the existing `IsActive`/lockout columns: locked is a temporary, auto-expiring brute-force lockout (see [Account Lockout](./account-security.md#account-lockout)); suspended is `UserSuspend`'s permanent-until-reactivated deactivation. `UserAuthHistory` is a lightweight proxy built from the Tokens table every other feature writes to — for a real persisted audit trail of named security events, see [Audit Log](#audit-log).

## Audit Log

`ezauth` persists a row to an audit log for security-relevant events — login success/failure, password reset, impersonation start/stop, account lockout, MFA enable/disable, user create/delete — automatically, via a built-in hook that wraps whatever `Hook` you register (see [Hooks](#hooks)) so it keeps working whether or not you set your own. Enabled by default; disable with `EZAUTH_AUDIT_LOG_ENABLED=false`.

```go
result, err := auth.Service.AuditLogs(ctx, targetUserID, service.ListAuditLogsOptions{
    EventType: models.AuditEventLoginFailed, // optional, e.g. "login.failed"
    Since:     &since,                       // optional, RFC3339
    Limit:     50,
})
// result.Events ([]*models.AuditLog: event_type, metadata, created_at), result.HasMore
```

Event types are the `models.AuditEvent*` constants (e.g. `AuditEventLoginSucceeded`, `AuditEventAccountLocked`). Two events — `AfterLoginFailed` and `AfterAccountLocked` — aren't tied to an existing `Hook` method, so they're added as new ones; embed `DefaultHook` as usual and only override what you need. "Email verification" and "role changes" aren't recorded yet since `ezauth` doesn't have an email-verification-confirm flow or RBAC.

For the JSON API: `GET /auth/api/admin/users/{id}/audit-logs` (query params `event_type`, `since`/`until` as RFC3339 timestamps, `limit`/`offset`; default 50, max 200) — same "no authz check, caller's responsibility" stance as the rest of [Admin User Management](#admin-user-management). Cookie clients use the same route under `/auth/admin/users/{id}/audit-logs`.

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
| `AfterImpersonationStarted`   | After an admin begins impersonating a user | No (errors are logged) |
| `AfterImpersonationEnded`     | After an impersonation session ends        | No (errors are logged) |
| `AfterMFAEnabled`             | After a user enables TOTP MFA              | No (errors are logged) |
| `AfterMFADisabled`            | After a user disables TOTP MFA             | No (errors are logged) |
| `AfterLoginFailed`            | After a failed login attempt (known user)  | No (errors are logged) |
| `AfterAccountLocked`          | After an account is locked out             | No (errors are logged) |

Every one of these also feeds the built-in [Audit Log](#audit-log) — your own hook and audit persistence both run, regardless of which `Hook` you register.

### Registering the Hook

```go
auth.SetHook(MyHook{
    db:  sqlDB,
    log: slog.Default(),
})
```

It's safe to call `SetHook` at any point — including after the server is running.
