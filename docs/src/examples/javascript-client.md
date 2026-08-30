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

### Step-up Login (Multi-Factor Authentication)

If the account has TOTP MFA enabled, `POST /auth/api/login` doesn't return tokens directly — it returns `{ "mfa_required": true, "mfa_token": "..." }` instead. Prompt the user for their authenticator code and exchange it (plus the `mfa_token`) at `POST /auth/api/mfa/login/verify` to get real session tokens. Passing `remember_device: true` returns a `device_token`; send it back via the `X-Device-Token` header on future logins to skip the step-up prompt for `EZAUTH_TRUSTED_DEVICE_TTL`.

```javascript
async function login(email, password) {
    const response = await fetch('/auth/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            // Send a previously-issued device token, if any, to skip MFA on trusted devices.
            'X-Device-Token': localStorage.getItem('device_token') || '',
        },
        body: JSON.stringify({ email, password })
    });

    if (!response.ok) return { ok: false };

    const { data } = await response.json();

    if (data.mfa_required) {
        // Stash the mfa_token; the UI should now prompt for a TOTP/recovery code.
        sessionStorage.setItem('mfa_token', data.mfa_token);
        return { ok: true, mfaRequired: true };
    }

    storeTokens(data);
    return { ok: true, mfaRequired: false };
}

async function verifyMFA(code, rememberDevice = false) {
    const mfaToken = sessionStorage.getItem('mfa_token');

    const response = await fetch('/auth/api/mfa/login/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfa_token: mfaToken, code, remember_device: rememberDevice })
    });

    if (!response.ok) return false; // wrong code — let the user retry

    const { data } = await response.json();
    sessionStorage.removeItem('mfa_token');

    if (data.device_token) {
        // Only present when remember_device was true; persist for the X-Device-Token header above.
        localStorage.setItem('device_token', data.device_token);
    }

    storeTokens(data);
    return true;
}

function storeTokens({ access_token, refresh_token }) {
    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);
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
