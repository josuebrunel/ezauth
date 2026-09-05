# Go Server Integration

This example demonstrates how to integrate `ezauth` into a standard Go web application using `chi` router and HTML templates.

The full source code is available in [`_example/go-server`](https://github.com/josuebrunel/ezauth/tree/main/_example/go-server).

## Overview

The application is a simple dashboard that requires user authentication. It uses `ezauth` for:

*   Registration (`/signup`)
*   Login (`/signin`)
*   Session management (Cookies)
*   Route protection
*   Profile updates

## Running the Example

You can run the example using Docker Compose:

```bash
cd _example/go-server
docker compose up --build
```

The server will be available at `http://localhost:3000`.

## Code Breakdown

### 1. Initialization

Initialize `ezauth` with configuration loaded from environment variables.

```go
// Load config
cfg, err := config.LoadConfig()
if err != nil {
    log.Fatalf("Failed to load config: %v", err)
}

// Initialize Auth
auth, err := ezauth.New(&cfg, "")
if err != nil {
    log.Fatalf("Failed to initialize auth: %v", err)
}

// Run Migrations (optional, but recommended for dev)
if err := auth.Migrate(); err != nil {
    log.Fatalf("Failed to migrate: %v", err)
}
```

### 2. Middleware Setup

Mount the session middleware. This is crucial for `GetSessionUser` and `IsAuthenticated` to work.

```go
r := chi.NewRouter()
r.Use(middleware.Logger)
r.Use(middleware.Recoverer)

// IMPORTANT: Session middleware
r.Use(auth.Handler.Session.LoadAndSave)
```

### 3. Mounting Routes

Mount the `ezauth` handler to handle all authentication routes (`/auth/*`).

```go
r.Mount("/auth", auth.Handler)
```

### 4. Protecting Routes

Use `auth.IsAuthenticated` to check if a user is logged in.

```go
r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
    // Check authentication
    if !auth.IsAuthenticated(r.Context()) {
        http.Redirect(w, r, "/signin", http.StatusSeeOther)
        return
    }

    // Get user details
    user, _ := auth.GetSessionUser(r.Context())

    renderTemplate(w, "dashboard.html", map[string]interface{}{
        "Title": "Dashboard - Dashy",
        "User":  user,
    })
})
```

### 5. Custom Handlers (Profile Update)

You can use `auth.Service` to perform user management operations directly.

```go
r.Post("/profile", func(w http.ResponseWriter, r *http.Request) {
    if !auth.IsAuthenticated(r.Context()) {
        http.Redirect(w, r, "/signin", http.StatusSeeOther)
        return
    }
    
    user, _ := auth.GetSessionUser(r.Context())

    if err := r.ParseForm(); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Update fields
    user.FirstName = r.FormValue("first_name")
    user.LastName = r.FormValue("last_name")

    // Save using Service
    if _, err := auth.Service.UserUpdate(r.Context(), user); err != nil {
        http.Error(w, "Failed to update profile", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/dashboard", http.StatusFound)
})

// Delete Profile
r.Post("/profile/delete", func(w http.ResponseWriter, r *http.Request) {
    if !auth.IsAuthenticated(r.Context()) {
        http.Redirect(w, r, "/signin", http.StatusSeeOther)
        return
    }

    user, _ := auth.GetSessionUser(r.Context())

    if err := auth.Service.UserDelete(r.Context(), user.ID); err != nil {
        http.Error(w, "Failed to delete profile", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/signin", http.StatusFound)
})
```

### 6. Roles, Organizations, and Scoped API Keys

Beyond session auth, `auth.Service` (or the top-level `auth.*` facade methods) exposes real RBAC, lightweight multi-tenancy, and scoped API keys — see [Roles & Permissions](../guides/admin-operations.md#roles--permissions-rbac), [Organizations](../guides/admin-operations.md#organizations), and [Scoped API Keys](../guides/account-security.md#scoped-api-keys) for the full reference. A one-time setup script for this dashboard app might look like:

```go
// Define a role once, then gate a route with it.
role, _ := auth.RoleCreate(ctx, "admin", "full dashboard access")
_ = auth.UserRoleGrant(ctx, user.ID, "admin")

r.With(auth.RequireRole("admin")).Get("/admin/settings", adminSettingsHandler)
```

```go
// Group users into an organization/team, each with a role scoped to that org.
org, _ := auth.OrganizationCreate(ctx, "Acme Inc")
_ = auth.OrgMemberAdd(ctx, org.ID, user.ID, "admin")
```

```go
// Mint a key limited to one action, for a machine client instead of a browser session.
key, _ := auth.APIKeyCreate(ctx, user.ID, []string{"reports:read"})
// key.Token is the raw key value — show it to the user now, it can't be recovered later.

r.Use(auth.APIKeyMiddleware) // group-level gate: any valid key of this user's gets past this
r.With(auth.RequireAPIKeyScope("reports:read")).Get("/api/reports", reportsHandler)
```

Refresh-token reuse detection needs no code at all: `TokenRefresh` (used internally by the `/auth/*` login/refresh flow this dashboard already relies on) automatically revokes an entire session family the moment an already-rotated-out refresh token is replayed — a strong signal of token theft.
