# Account Security

Second-factor and hardening features: MFA, session revocation, account lockout, guarded email changes, and asymmetric JWT signing.

## Token Storage

Every bearer-style token `ezauth` issues — refresh tokens, password-reset and passwordless magic links, API keys, MFA pre-auth tokens, MFA recovery codes, SMS OTP codes, trusted-device tokens, invitations, and email-change confirmation links — is stored and looked up by its SHA-256 hash (see `util.HashToken`), never the raw value. These are high-entropy random values, not passwords, so an unsalted hash is sufficient. A database-read compromise therefore doesn't hand over directly usable credentials. This is transparent to callers — `APIKeyCreate`, `TokenCreate`, `InvitationCreate`, etc. still return/email the raw value exactly as before, only the stored representation changed. See the [README's Token Storage section](https://github.com/josuebrunel/ezauth#token-storage) for more.

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

`MFALoginVerify` and `MFADisable` reject a TOTP code that already succeeded once, even if it's still within its ~30s validity window (plus clock-skew allowance) — per RFC 6238 §5.2, this closes the window a code captured via phishing or shoulder-surfing would otherwise stay usable in for a second, attacker-controlled session.

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

### Refresh Token Reuse Detection

Needs no code or configuration — it's automatic. Every refresh token is tagged with a rotation `family_id`, carried forward across `TokenRefresh` rotations. If an already-rotated-out (revoked) refresh token is ever replayed, that's a strong signal it was stolen and the legitimate client has since rotated past it — so `TokenRefresh` responds by revoking every other active token in that family in one bulk operation, not just rejecting the replayed one. In practice: if an attacker steals a refresh token and uses it after the real client already refreshed past it, both the attacker's and the legitimate client's sessions get logged out, forcing a fresh login.

## Account Lockout

`UserAuthenticate` enforces `IsActive` as a login gate and counts consecutive failed attempts, locking the account (clearing `IsActive`) for `EZAUTH_ACCOUNT_LOCKOUT_DURATION` after `EZAUTH_ACCOUNT_LOCKOUT_MAX_ATTEMPTS` in a row; it auto-unlocks (and resets the counter) on the first login attempt after that window passes. A successful login resets the counter immediately.

`MFALoginVerify` and `SMSOTPVerify` share this same counter and lockout: an invalid TOTP/recovery code or SMS code counts toward the same `EZAUTH_ACCOUNT_LOCKOUT_MAX_ATTEMPTS` threshold as a wrong password, and once locked, both reject even a *correct* code until the account unlocks. This is what actually bounds brute-force guessing against those codes — the global rate limiter (`EZAUTH_RATE_LIMIT_ENABLED`, on by default) is a separate, coarser IP-based control.

```go
_, err := auth.Service.UserAuthenticate(ctx, req)
switch {
case errors.Is(err, service.ErrAccountLocked):
    // Too many recent failed attempts; auto-expires.
case errors.Is(err, service.ErrAccountDisabled):
    // IsActive is false for some other reason (no auto-expiry).
}
```

The built-in `Login`/`FormLogin` handlers don't surface this distinction to the caller: they always return a generic "invalid credentials" message regardless of cause, since `ErrAccountLocked`/`ErrAccountDisabled` only ever apply to an account that exists -- surfacing them verbatim would let an anonymous caller enumerate account existence/lockout state. Build on `Service.UserAuthenticate` directly (as above) if you want the specific reason in an already-authenticated context.

Set `EZAUTH_ACCOUNT_LOCKOUT_ENABLED=false` to stop counting/locking on failed attempts while still enforcing `IsActive` for accounts disabled some other way; `MAX_ATTEMPTS`/`DURATION` keep their normal defaults regardless, so this alone is enough. `config.LoadConfig()` fails at startup if `ENABLED`/`MAX_ATTEMPTS`/`DURATION` *all* resolve to zero, since that combination can only come from a misconfigured deployment, never a deliberate choice to disable lockout.

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
r.Use(auth.Handler.APIKeyMiddleware) // group-level gate: any valid key gets past this
r.With(auth.RequireAPIKeyScope("posts:write")).Post("/posts", createPostHandler)
```

> **Warning:** an unscoped key has full access, not restricted access. `APIKeyCreate(ctx, userID, nil)` does **not** create a key with no permissions — it creates a key that passes every `RequireAPIKeyScope` check unconditionally, identically to a key issued before scoping existed. Always pass an explicit non-empty scopes list for any key that should be limited. The master `EZAUTH_API_KEY` config key has no associated `Token` at all, so it's always unscoped/full-access too, regardless of any `RequireAPIKeyScope` check.

See the [Scoped API Keys section of the README](https://github.com/josuebrunel/ezauth#scoped-api-keys) for more.
