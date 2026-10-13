# Admin Panel

[ezauth-admin](https://github.com/josuebrunel/ezauth-admin) is an admin panel for EzAuth. It is a separate project that you mount in your own app, on top of your existing EzAuth instance: no extra service, no extra deployment, and no migrations of its own.

## What you get

- **Dashboard:** user counts, a 14-day sign-ups chart and the latest activity.
- **Users:** search, filter by status, edit a profile, suspend and reactivate, delete, impersonate, and keep admin-only notes.
- **Invitations:** invite someone by email with the roles you pick, see who hasn't accepted yet, and resend or revoke. The invitee follows the link to an accept page in your app (see [Invitation-Based Onboarding](admin-operations.md#invitation-based-onboarding)), and the panel shows the link too, for when email isn't set up.
- **Roles and permissions:** create and delete them, give permissions to roles, give roles to users.
- **Audit log:** sign-ins, role changes, impersonation and deletions across all users, filterable and paged.

It is server-rendered (Templ and HTMX), styled with DaisyUI, supports light and dark themes, and embeds all of its assets, so it makes no requests to third-party servers.

## Requirements

- EzAuth **v0.32.0** or newer. The panel uses `AuditLogsAll`, `UserStats`, `UserSignups` and `UserProfileUpdate` (v0.31.0), and `InvitationIssue`, `InvitationsAll` and `InvitationRevokeByID` (v0.32.0).
- Go 1.25.4 or newer.
- `auth.SessionMiddleware` on the router the panel is mounted on.

## Install

```sh
go get github.com/josuebrunel/ezauth-admin
```

## Mount it

### chi

```go
import (
    "github.com/josuebrunel/ezauth"
    "github.com/josuebrunel/ezauth-admin/admin"
)

auth, _ := ezauth.New(&cfg, "") // "" because Mount adds the /auth prefix
_ = auth.Migrate()

panel, _ := admin.New(auth, admin.WithAppName("Acme"))

r := chi.NewRouter()
r.Use(auth.SessionMiddleware)
r.Mount("/auth", auth.Handler)
r.Mount("/admin", panel.Handler())
```

### net/http

```go
auth, _ := ezauth.New(&cfg, "") // "" because StripPrefix removes /auth
panel, _ := admin.New(auth)

mux := http.NewServeMux()
mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler))
mux.Handle("/admin/", panel.Handler())
mux.Handle("/admin", panel.Handler())

http.ListenAndServe(":8080", auth.SessionMiddleware(mux))
```

The panel is an `http.Handler`, so any router that can mount one works. It removes its own base path from the request, so it doesn't matter whether your router strips the prefix first.

## Options

| Option | Default | What it does |
|---|---|---|
| `WithBasePath(path)` | `/admin` | The URL prefix the panel is mounted at. It must match your router, because the panel writes its links from it. |
| `WithRole(role)` | `EZAUTH_ADMIN_ROLE` (`admin`) | The RBAC role that opens the panel. |
| `WithAppName(name)` | `EzAuth` | The name in the sidebar and page titles. |
| `WithDashboardCache(ttl)` | `30s` | How long the dashboard reuses its user counts. `0` counts on every load. |

## Sign in as an admin

The panel is for users who hold the admin role, so someone has to be the first. Use the CLI:

```sh
ezauthapi create-admin -email=you@example.com -password=<a-strong-password>
```

Then sign in and open `/admin/`.

## How access works

The panel closes everything by default.

- Signed-out visitors are redirected to your login page (`EZAUTH_LOGIN_PAGE_URL`).
- Signed-in users without the role get a `403`.
- State-changing requests are checked for same-origin (CSRF) with the browser's Fetch Metadata headers. There is no token to add.
- The panel calls `service.Auth` methods, which do no authorization of their own, so it does the checking itself, on every route.
- An admin can't suspend, delete or impersonate their own account, or revoke their own admin role, so there is always an admin left.

## Invitations

The emailed link lands on your app, not on the panel, so your app needs an accept page: EzAuth sends the invitee to `EZAUTH_INVITATION_ACCEPT_PAGE_URL` (default `/invitation/accept`), and that page posts to `POST /auth/invitation/accept`. Set `EZAUTH_BASE_URL` to your public address, or the link will point at localhost. With no SMTP configured nothing is emailed, and the panel shows the link for you to share. The [panel's mounting guide](https://github.com/josuebrunel/ezauth-admin/blob/main/docs/mounting.md#invitations) has the details and a working example page.

## Troubleshooting

**Signing in returns a 404.** `ezauth.New` was given the path `"auth"` but your router already strips `/auth`. Pass `""` when you mount at `/auth`.

**Every panel page returns a 500.** The router doesn't run `auth.SessionMiddleware`. Add it. The panel stays closed in the meantime, and the log says what to do.

**Signing in loops back to the login page.** Your login page must live outside `/auth/*` and `/admin/*`. Point `EZAUTH_LOGIN_PAGE_URL` at it.

The [panel's own mounting guide](https://github.com/josuebrunel/ezauth-admin/blob/main/docs/mounting.md) has the full list, and a [Docker demo](https://github.com/josuebrunel/ezauth-admin#try-it) with preloaded users you can run in one command.
