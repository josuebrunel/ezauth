# Javascript Client

This example demonstrates how to interact with `ezauth`'s JSON API using a Javascript client (SPA style).

The full source code is available in [`_example/javascript-client`](https://github.com/josuebrunel/ezauth/tree/main/_example/javascript-client).

## Overview

In this scenario, `ezauth` acts as a backend API. The Go server (`main.go`) serves static HTML/JS files, and the browser communicates directly with the `ezauth` endpoints mounted at `/auth`.

*   **API Registration**: `POST /auth/api/register`
*   **API Login**: `POST /auth/api/login`
*   **User Info**: `GET /auth/api/userinfo`
*   **Logout**: `POST /auth/api/logout`

## Backend Setup

The Go server simply mounts `ezauth` and serves static files.

```go
// Initialize ezauth with "auth" path prefix
authApp, _ := ezauth.New(&cfg, "auth")

// Mount handler
r.Handle("/auth/*", authApp.Handler)

// Serve static files
r.Handle("/*", http.FileServer(http.FS(staticFS)))
```

## Frontend Logic

### Login

Send a JSON request to `/auth/api/login`. The server verifies credentials and returns Access and Refresh tokens.

```javascript
async function login(email, password) {
    const response = await fetch('/auth/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
    });

    if (response.ok) {
        const data = await response.json();
        const { access_token, refresh_token } = data.data; // ezauth returns { data: ... } wrapped response
        
        // Store tokens (localStorage for simplicity, but treat carefully)
        localStorage.setItem('access_token', access_token);
        localStorage.setItem('refresh_token', refresh_token);
        
        return true;
    }
    return false;
}
```

### Accessing Protected Resources

To access protected endpoints (like `/auth/api/userinfo`), include the Access Token in the `Authorization` header.

```javascript
async function getUserInfo() {
    const token = localStorage.getItem('access_token');
    
    const response = await fetch('/auth/api/userinfo', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });

    if (response.ok) {
        const data = await response.json();
        return data.data; // The user object
    }
    return null;
}
```

### Token Refresh

`ezauth` provides a refresh endpoint. When the access token expires (401 Unauthorized), use the refresh token to get a new one.

```javascript
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    
    const response = await fetch('/auth/api/token/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken })
    });

    if (response.ok) {
        const data = await response.json();
        localStorage.setItem('access_token', data.data.access_token);
        localStorage.setItem('refresh_token', data.data.refresh_token); // Update refresh token if rotated
        return true;
    }
    return false;
}
```
