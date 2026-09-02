# Sign-in Methods

Email/password, magic-link (passwordless), and password-reset flows are built in — see the [API Endpoints](../api-endpoints.md) reference. The sections below cover the additional sign-in methods.

## OAuth2 & OIDC Providers

`ezauth` ships presets for the most common providers — Google, GitHub, Facebook, Discord, GitLab, Slack, LinkedIn, and Spotify. Each is enabled by setting its `EZAUTH_OAUTH2_<NAME>_*` variables (see [Configuration > OAuth2 Settings](../configuration.md#oauth2-settings)); the routes live under `/auth/oauth2/{provider}/login` and `/auth/oauth2/{provider}/callback` (see [API Endpoints](../api-endpoints.md)). You can also register arbitrary custom or OIDC providers, as shown below.

> [!IMPORTANT]
> OAuth2 auto-linking requires the provider to return `email_verified: true` in the user info response. If a provider does not return this field (or returns `false`), the user will be prompted to log in with their existing password rather than being automatically linked. This prevents account takeover via unverified email addresses.

### Custom / OIDC Providers

You can register custom providers dynamically via environment variables (Standalone-service mode) or in Go code (Library mode).

#### Standalone-service mode (via Env Vars)
1. Add your provider's name to `EZAUTH_OAUTH2_PROVIDERS` (comma-separated).
2. Configure prefix variables for each provider (`EZAUTH_OAUTH2_<NAME>_`):
  - `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URL` (required)
  - `SCOPES` (optional, comma-separated)
  - Either `ISSUER_URL` (for automatic OIDC discovery) or manual endpoint parameters (`AUTH_URL`, `TOKEN_URL`, `USERINFO_URL`, `ID_FIELD` (default `id`), `EMAIL_FIELD` (default `email`)).

#### Library Mode (Go Code)
Register providers programmatically with the `RegisterOAuth2Provider` API. We ship pre-made presets (Discord, Slack, GitLab) and a generic OIDC discovery helper in the optional `github.com/josuebrunel/ezauth/pkg/service/providers` package:

```go
import (
    "github.com/josuebrunel/ezauth/pkg/service/providers"
)

// 1. OIDC Discovery
oktaProvider, err := providers.OIDC(ctx, "https://your-domain.okta.com", "client-id", "client-secret", "http://localhost:8080/auth/oauth2/okta/callback", []string{"openid", "profile", "email"})
if err == nil {
    auth.RegisterOAuth2Provider("okta", oktaProvider)
}

// 2. Out-of-the-box Preset
discordProvider := providers.Discord("client-id", "client-secret", "http://localhost:8080/auth/oauth2/discord/callback")
auth.RegisterOAuth2Provider("discord", discordProvider)
```

## SMS OTP

`ezauth` supports SMS-based one-time-password login, mirroring the passwordless (magic link) flow but via a 6-digit SMS code. An unrecognized phone number gets a temporary, unverified account, same as an unrecognized email does for passwordless. Requires `EZAUTH_SMS_TWILIO_ACCOUNT_SID`/`_AUTH_TOKEN`/`_FROM`; falls back to a mock sender otherwise. Phone numbers are enforced unique at the database level.

```go
err := auth.Service.SMSOTPRequest(ctx, service.RequestSMSOTP{Phone: "+15551234567"})

tokens, err := auth.Service.SMSOTPVerify(ctx, service.RequestSMSOTPVerify{
    Phone: "+15551234567",
    Code:  "123456",
})
```

`EZAUTH_SMS_OTP_BODY` customizes the SMS message template (`{{.Code}}`, `{{.Phone}}` available).

## WebAuthn / Passkeys

`ezauth` supports WebAuthn/FIDO2 passkey registration and login. Login is **discoverable (usernameless)** — the browser's platform UI lets the user pick a passkey, so no prior email/username is required. WebAuthn is disabled unless `EZAUTH_WEBAUTHN_RP_ID` and `EZAUTH_WEBAUTHN_RP_ORIGINS` are both set, and ceremonies always require client-side JavaScript (`navigator.credentials.create()`/`.get()`) regardless of cookie vs. Bearer auth style.

```go
// Registration (user already authenticated):
creation, sessionKey, err := auth.WebauthnBeginRegistration(ctx, user)
// Send creation as JSON for the browser to call navigator.credentials.create(),
// keep sessionKey for the finish step.

// r's body must be the browser's raw navigator.credentials.create() response.
cred, err := auth.WebauthnFinishRegistration(ctx, user, sessionKey, r, "YubiKey 5")

// Login:
assertion, sessionKey, err := auth.WebauthnBeginLogin(ctx)
// Send assertion as JSON for the browser to call navigator.credentials.get().

// r's body must be the browser's raw navigator.credentials.get() response.
user, tokens, err := auth.WebauthnFinishLogin(ctx, sessionKey, r)

// Managing credentials:
creds, err := auth.WebauthnCredentials(ctx, user.ID)
err = auth.WebauthnDeleteCredential(ctx, user, credentialRecordID)
```
