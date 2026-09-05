# Account Security

Second-factor and hardening features: MFA, session revocation, account lockout, guarded email changes, and asymmetric JWT signing.

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

## Sessions

Every refresh token issued to a user (one per login, across devices/clients) is a session. Let users see and remotely revoke their own active sessions — e.g. a "log out other devices" account-security page.

```go
sessions, err := auth.Sessions(ctx, user.ID)
// []service.SessionInfo{ID, CreatedAt, ExpiresAt}, most recent first.

err = auth.RevokeSession(ctx, user, sessions[0].ID)      // log out one device
err = auth.RevokeAllSessions(ctx, user, currentID)        // log out other devices, keep currentID
err = auth.RevokeAllSessions(ctx, user, "")                // log out everywhere
```

For the JSON API: `GET /auth/api/sessions` lists sessions, `DELETE /auth/api/sessions/{id}` revokes one, and `DELETE /auth/api/sessions?except={id}` revokes all but the session named by `except` (omit `except` to log out everywhere). Cookie clients use the same routes under `/auth/sessions[...]`.

## Account Lockout

`UserAuthenticate` enforces `IsActive` as a login gate and counts consecutive failed attempts, locking the account (clearing `IsActive`) for `EZAUTH_ACCOUNT_LOCKOUT_DURATION` after `EZAUTH_ACCOUNT_LOCKOUT_MAX_ATTEMPTS` in a row; it auto-unlocks (and resets the counter) on the first login attempt after that window passes. A successful login resets the counter immediately.

```go
_, err := auth.Service.UserAuthenticate(ctx, req)
switch {
case errors.Is(err, service.ErrAccountLocked):
    // Too many recent failed attempts; auto-expires.
case errors.Is(err, service.ErrAccountDisabled):
    // IsActive is false for some other reason (no auto-expiry).
}
```

Set `EZAUTH_ACCOUNT_LOCKOUT_ENABLED=false` to stop counting/locking on failed attempts while still enforcing `IsActive` for accounts disabled some other way.

## Guarded Email Change

Changing the account email is a distinct, security-sensitive operation, handled the same way password reset already is: the current password is required to initiate, the new address must be verified via an emailed link before the change takes effect (the old address stays active until then), and the old address gets a notice of the pending change. Confirming revokes every other session.

```go
err := auth.Service.EmailChangeRequest(ctx, user, service.RequestEmailChange{
    CurrentPassword: "their-current-password",
    NewEmail:        "new-address@example.com",
})

updated, err := auth.Service.EmailChangeConfirm(ctx, tokenFromLink)
```

`EZAUTH_EMAIL_CHANGE_SUBJECT`/`EZAUTH_EMAIL_CHANGE_BODY` customize the verification email sent to the new address; `EZAUTH_EMAIL_CHANGE_NOTIFY_SUBJECT`/`EZAUTH_EMAIL_CHANGE_NOTIFY_BODY` customize the notice sent to the old one (`{{.NewEmail}}` available in both).

## Asymmetric JWT Signing (JWKS)

By default `ezauth` signs access tokens with symmetric HS256 (`EZAUTH_JWT_SECRET`) — any resource server verifying tokens itself must hold that same secret. Set `EZAUTH_JWT_ALGORITHM=RS256` or `EdDSA` (plus PEM-encoded `EZAUTH_JWT_PRIVATE_KEY`/`EZAUTH_JWT_PUBLIC_KEY`) to sign asymmetrically instead: `ezauth` keeps the private key, and independent resource servers verify tokens against the public key published at `GET /.well-known/jwks.json` — no shared secret required.

```go
set := auth.JWKS() // service.JWKSet{Keys: []service.JWK} — empty for the default HS256 mode
```

**Key rotation**: each key gets a `kid`, either explicit (`EZAUTH_JWT_KEY_ID`) or auto-derived from the public key. To rotate without invalidating already-issued tokens, move the outgoing key's public key/kid to `EZAUTH_JWT_PREVIOUS_PUBLIC_KEY`/`EZAUTH_JWT_PREVIOUS_KEY_ID` and point `EZAUTH_JWT_PRIVATE_KEY`/`PUBLIC_KEY`/`KEY_ID` at the new key — new tokens sign under the new key while tokens already signed under the previous one keep verifying (both are published in the JWKS) until they expire naturally (access tokens are short-lived, 1 hour).

See the [Asymmetric JWT Signing section of the README](https://github.com/josuebrunel/ezauth#asymmetric-jwt-signing-jwks) for a full config example.

## Scoped API Keys

By default an API key (via `APIKeyMiddleware`) grants the same access as the full account. `APIKeyCreate` can limit a key to a specific set of scopes, enforced per-route with `RequireAPIKeyScope`, layered on top of `APIKeyMiddleware`'s existing all-or-nothing group-level gate.

```go
token, err := auth.Service.APIKeyCreate(ctx, user.ID, []string{"posts:write"})
// token.Token is the raw key value — store/display it now, it can't be recovered later.

keys, err := auth.Service.APIKeysList(ctx, user.ID) // []service.APIKeyInfo — raw key omitted, shown only once above
err = auth.Service.APIKeyRevoke(ctx, user.ID, token.ID) // fails with service.ErrAPIKeyNotFound if the key isn't user's
```

```go
r.Use(auth.APIKeyMiddleware) // group-level gate: any valid key gets past this
r.With(auth.RequireAPIKeyScope("posts:write")).Post("/posts", createPostHandler)
```

An **unscoped** key — `APIKeyCreate(ctx, userID, nil)`, or any key issued before this feature existed — has full access to every `RequireAPIKeyScope` check; only a key created with a non-empty scopes list is actually restricted. The master `EZAUTH_API_KEY` config key has no associated `Token` at all, so it's always unscoped/full-access too.

See the [Scoped API Keys section of the README](https://github.com/josuebrunel/ezauth#scoped-api-keys) for more.
