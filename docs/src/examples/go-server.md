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
