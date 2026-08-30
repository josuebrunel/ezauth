# Configuration

`ezauth` is configured primarily through environment variables. All variables are prefixed with `EZAUTH_`.

## Global Settings

| Variable            | Description                                         | Default                 |
| ------------------- | --------------------------------------------------- | ----------------------- |
| `EZAUTH_ADDR`       | The address the server listens on.                  | `:8080`                 |
| `EZAUTH_API_KEY`    | Master API Key for protecting endpoints.            |                         |
| `EZAUTH_BASE_URL`   | The base URL of the auth service (used for emails). | `http://localhost:8080` |
| `EZAUTH_DEBUG`      | Enable debug logging.                               | `false`                 |
| `EZAUTH_JWT_SECRET`    | Secret key used to sign JWT tokens.                            |                         |
| `EZAUTH_CSRF_SECRET`   | Secret key for CSRF protection. Falls back to JWT_SECRET.     | (falls back to JWT_SECRET) |
| `EZAUTH_TIMEOUT`       | Request timeout duration.                                      | `30s`                   |
| `EZAUTH_MFA_ISSUER`    | Issuer name shown in authenticator apps for TOTP MFA.          | `EzAuth`                |
| `EZAUTH_TRUSTED_DEVICE_TTL`         | How long a "remembered" device skips MFA step-up.  | `720h` (30 days)        |
| `EZAUTH_TRUSTED_DEVICE_COOKIE_NAME` | Cookie name for the trusted-device token (form/cookie clients). | `ezauth_device` |

## WebAuthn/Passkey Settings

WebAuthn support is disabled unless both `EZAUTH_WEBAUTHN_RP_ID` and `EZAUTH_WEBAUTHN_RP_ORIGINS` are set.

| Variable                          | Description                                                        | Default  |
| ---------------------------------- | ------------------------------------------------------------------ | -------- |
| `EZAUTH_WEBAUTHN_RP_ID`            | Relying Party ID: the effective domain (e.g. `example.com`, no scheme/port). |          |
| `EZAUTH_WEBAUTHN_RP_DISPLAY_NAME`  | Relying Party display name shown during registration.              | `EzAuth` |
| `EZAUTH_WEBAUTHN_RP_ORIGINS`       | Comma-separated list of allowed origins (e.g. `https://example.com`). |          |

## Hashing Settings

| Variable                               | Description                                                                      | Default |
| -------------------------------------- | -------------------------------------------------------------------------------- | ------- |
| `EZAUTH_HASHING_ALGORITHM`             | Password hashing algorithm (`bcrypt` or `argon2id`).                             | `bcrypt`|
| `EZAUTH_HASHING_ARGON2_MEMORY`         | Argon2 memory cost in KB (used when algorithm is `argon2id`).                    | `65536` |
| `EZAUTH_HASHING_ARGON2_ITERATIONS`     | Argon2 time cost (iterations).                                                   | `3`     |
| `EZAUTH_HASHING_ARGON2_PARALLELISM`    | Argon2 parallelism (thread count).                                               | `4`     |

## Rate Limit Settings

| Variable                         | Description                                              | Default  |
| -------------------------------- | -------------------------------------------------------- | -------- |
| `EZAUTH_RATE_LIMIT_ENABLED`      | Enable rate limiting on authentication endpoints.        | `false`  |
| `EZAUTH_RATE_LIMIT_REQUESTS`     | Maximum requests allowed per window.                     | `10`     |
| `EZAUTH_RATE_LIMIT_WINDOW`       | Rate limit window duration (e.g., `1m`, `30s`).          | `1m`     |
| `EZAUTH_RATE_LIMIT_BY_CLIENT_IP` | Apply rate limiting per client IP address.               | `true`   |

## Database Settings

| Variable            | Description                                           | Default     |
| ------------------- | ----------------------------------------------------- | ----------- |
| `EZAUTH_DB_DIALECT` | Database dialect (`sqlite3`, `postgres`, or `mysql`). | `sqlite3`   |
| `EZAUTH_DB_DSN`     | Database connection string.                           | `ezauth.db` |
| `EZAUTH_DB_SCHEMA`  | Database schema (PostgreSQL only).                    | `public`    |

## SMTP Settings

Used for sending password reset and magic link emails.

| Variable               | Description                     | Default               |
| ---------------------- | ------------------------------- | --------------------- |
| `EZAUTH_SMTP_HOST`     | SMTP server host.               |                       |
| `EZAUTH_SMTP_PORT`     | SMTP server port.               | `587`                 |
| `EZAUTH_SMTP_USER`     | SMTP username.                  |                       |
| `EZAUTH_SMTP_PASSWORD` | SMTP password.                  |                       |
| `EZAUTH_SMTP_FROM`     | The email address to send from. | `noreply@example.com` |

## Email Templates

Customize the subject and body of emails sent by `ezauth`. Templates use Go `text/template` syntax.

**Available variables:** `{{.Link}}` (action URL), `{{.Token}}` (raw token), `{{.Email}}` (user's email)

| Variable                              | Description                        | Default                                                      |
| ------------------------------------- | ---------------------------------- | ------------------------------------------------------------ |
| `EZAUTH_EMAIL_PASSWORDLESS_SUBJECT`   | Subject for magic link emails.     | `Magic Link Login`                                           |
| `EZAUTH_EMAIL_PASSWORDLESS_BODY`      | Body for magic link emails.        | `Click the following link to login: {{.Link}}`               |
| `EZAUTH_EMAIL_PASSWORD_RESET_SUBJECT` | Subject for password reset emails. | `Password Reset Request`                                     |
| `EZAUTH_EMAIL_PASSWORD_RESET_BODY`    | Body for password reset emails.    | `Click the following link to reset your password: {{.Link}}` |

## SMS OTP Settings

Used for sending SMS one-time login codes. SMS OTP support falls back to a mock sender (no message actually sent) unless all three of `EZAUTH_SMS_TWILIO_ACCOUNT_SID`, `EZAUTH_SMS_TWILIO_AUTH_TOKEN`, and `EZAUTH_SMS_TWILIO_FROM` are set.

| Variable                        | Description                              | Default |
| -------------------------------- | ----------------------------------------- | ------- |
| `EZAUTH_SMS_TWILIO_ACCOUNT_SID`  | Twilio Account SID.                       |         |
| `EZAUTH_SMS_TWILIO_AUTH_TOKEN`   | Twilio Auth Token.                        |         |
| `EZAUTH_SMS_TWILIO_FROM`         | The phone number to send from.            |         |
| `EZAUTH_SMS_OTP_BODY`            | SMS body template. `{{.Code}}`, `{{.Phone}}` available. | `Your verification code is: {{.Code}}` |

## Form/Redirect Settings

Used for the Form-based handlers (browser flows).

| Variable                         | Description                                       | Default     |
| -------------------------------- | ------------------------------------------------- | ----------- |
| `EZAUTH_REDIRECT_AFTER_LOGIN`    | URL to redirect to after successful login.        | `/`         |
| `EZAUTH_REDIRECT_AFTER_REGISTER` | URL to redirect to after successful registration. | `/`         |
| `EZAUTH_LOGIN_PAGE_URL`          | URL of your custom Login page (for redirects).    | `/login`    |
| `EZAUTH_REGISTER_PAGE_URL`       | URL of your custom Register page (for redirects). | `/register` |
| `EZAUTH_MFA_VERIFY_PAGE_URL`     | URL of your custom MFA code-entry page (for step-up login redirects). | `/mfa/verify` |

## OAuth2 Settings

### General
| Variable                     | Description                                                    |
| ---------------------------- | -------------------------------------------------------------- |
| `EZAUTH_OAUTH2_CALLBACK_URL` | The URL users are redirected to after successful OAuth2 login. |

### Google
| Variable                             | Description                                                                                  | Default                |
| ------------------------------------ | -------------------------------------------------------------------------------------------- | ---------------------- |
| `EZAUTH_OAUTH2_GOOGLE_CLIENT_ID`     | Google OAuth2 Client ID.                                                                     |
| `EZAUTH_OAUTH2_GOOGLE_CLIENT_SECRET` | Google OAuth2 Client Secret.                                                                 |
| `EZAUTH_OAUTH2_GOOGLE_REDIRECT_URL`  | Redirect URL registered in Google Console. Must be: `{base_url}/auth/oauth2/google/callback` |
| `EZAUTH_OAUTH2_GOOGLE_SCOPES`        | Scopes to request.                                                                           | `openid,profile,email` |

### GitHub
| Variable                             | Description                                                                                   | Default      |
| ------------------------------------ | --------------------------------------------------------------------------------------------- | ------------ |
| `EZAUTH_OAUTH2_GITHUB_CLIENT_ID`     | GitHub OAuth2 Client ID.                                                                      |              |
| `EZAUTH_OAUTH2_GITHUB_CLIENT_SECRET` | GitHub OAuth2 Client Secret.                                                                  |              |
| `EZAUTH_OAUTH2_GITHUB_REDIRECT_URL`  | Redirect URL registered in GitHub settings. Must be: `{base_url}/auth/oauth2/github/callback` |              |
| `EZAUTH_OAUTH2_GITHUB_SCOPES`        | Scopes to request.                                                                            | `user:email` |

### Facebook
| Variable                               | Description                                                                                       | Default                |
| -------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------- |
| `EZAUTH_OAUTH2_FACEBOOK_CLIENT_ID`     | Facebook OAuth2 Client ID.                                                                        |                        |
| `EZAUTH_OAUTH2_FACEBOOK_CLIENT_SECRET` | Facebook OAuth2 Client Secret.                                                                    |                        |
| `EZAUTH_OAUTH2_FACEBOOK_REDIRECT_URL`  | Redirect URL registered in Facebook settings. Must be: `{base_url}/auth/oauth2/facebook/callback` |                        |
| `EZAUTH_OAUTH2_FACEBOOK_SCOPES`        | Scopes to request.                                                                                | `email,public_profile` |

### Discord
| Variable                              | Description                                                                                     | Default          |
| ------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------------- |
| `EZAUTH_OAUTH2_DISCORD_CLIENT_ID`     | Discord OAuth2 Client ID.                                                                       |                  |
| `EZAUTH_OAUTH2_DISCORD_CLIENT_SECRET` | Discord OAuth2 Client Secret.                                                                   |                  |
| `EZAUTH_OAUTH2_DISCORD_REDIRECT_URL`  | Redirect URL registered in Discord settings. Must be: `{base_url}/auth/oauth2/discord/callback` |                  |
| `EZAUTH_OAUTH2_DISCORD_SCOPES`        | Scopes to request.                                                                              | `identify,email` |

### GitLab
| Variable                             | Description                                                                                   | Default     |
| ------------------------------------ | --------------------------------------------------------------------------------------------- | ----------- |
| `EZAUTH_OAUTH2_GITLAB_CLIENT_ID`     | GitLab OAuth2 Client ID.                                                                      |             |
| `EZAUTH_OAUTH2_GITLAB_CLIENT_SECRET` | GitLab OAuth2 Client Secret.                                                                  |             |
| `EZAUTH_OAUTH2_GITLAB_REDIRECT_URL`  | Redirect URL registered in GitLab settings. Must be: `{base_url}/auth/oauth2/gitlab/callback` |             |
| `EZAUTH_OAUTH2_GITLAB_SCOPES`        | Scopes to request.                                                                            | `read_user` |

### Slack
| Variable                            | Description                                                                                 | Default        |
| ----------------------------------- | ------------------------------------------------------------------------------------------- | -------------- |
| `EZAUTH_OAUTH2_SLACK_CLIENT_ID`     | Slack OAuth2 Client ID.                                                                     |                |
| `EZAUTH_OAUTH2_SLACK_CLIENT_SECRET` | Slack OAuth2 Client Secret.                                                                 |                |
| `EZAUTH_OAUTH2_SLACK_REDIRECT_URL`  | Redirect URL registered in Slack settings. Must be: `{base_url}/auth/oauth2/slack/callback` |                |
| `EZAUTH_OAUTH2_SLACK_SCOPES`        | Scopes to request.                                                                          | `openid,email` |

### LinkedIn
| Variable                               | Description                                                                                       | Default                |
| -------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------- |
| `EZAUTH_OAUTH2_LINKEDIN_CLIENT_ID`     | LinkedIn OAuth2 Client ID.                                                                        |                        |
| `EZAUTH_OAUTH2_LINKEDIN_CLIENT_SECRET` | LinkedIn OAuth2 Client Secret.                                                                    |                        |
| `EZAUTH_OAUTH2_LINKEDIN_REDIRECT_URL`  | Redirect URL registered in LinkedIn settings. Must be: `{base_url}/auth/oauth2/linkedin/callback` |                        |
| `EZAUTH_OAUTH2_LINKEDIN_SCOPES`        | Scopes to request.                                                                                | `openid,profile,email` |

### Spotify
| Variable                              | Description                                                                                     | Default                             |
| ------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------- |
| `EZAUTH_OAUTH2_SPOTIFY_CLIENT_ID`     | Spotify OAuth2 Client ID.                                                                       |                                     |
| `EZAUTH_OAUTH2_SPOTIFY_CLIENT_SECRET` | Spotify OAuth2 Client Secret.                                                                   |                                     |
| `EZAUTH_OAUTH2_SPOTIFY_REDIRECT_URL`  | Redirect URL registered in Spotify settings. Must be: `{base_url}/auth/oauth2/spotify/callback` |                                     |
| `EZAUTH_OAUTH2_SPOTIFY_SCOPES`        | Scopes to request.                                                                              | `user-read-email,user-read-private` |

### Custom OAuth2 Providers

For providers not in the built-in list, use the dynamic provider configuration:

| Variable                             | Description                                                       |
| ------------------------------------ | ----------------------------------------------------------------- |
| `EZAUTH_OAUTH2_PROVIDERS`            | Comma-separated list of custom provider names to register.        |
| `EZAUTH_OAUTH2_<NAME>_CLIENT_ID`     | OAuth2 Client ID for the custom provider.                         |
| `EZAUTH_OAUTH2_<NAME>_CLIENT_SECRET` | OAuth2 Client Secret for the custom provider.                     |
| `EZAUTH_OAUTH2_<NAME>_REDIRECT_URL`  | Redirect URL for the custom provider.                             |
| `EZAUTH_OAUTH2_<NAME>_SCOPES`        | Comma-separated scopes to request.                                |
| `EZAUTH_OAUTH2_<NAME>_ISSUER_URL`    | OIDC Issuer URL (enables automatic OIDC discovery).               |
| `EZAUTH_OAUTH2_<NAME>_AUTH_URL`      | Authorization endpoint (manual config, requires TOKEN_URL).       |
| `EZAUTH_OAUTH2_<NAME>_TOKEN_URL`     | Token endpoint (manual config, requires AUTH_URL).                |
| `EZAUTH_OAUTH2_<NAME>_USERINFO_URL`  | Userinfo endpoint (manual config, requires AUTH_URL + TOKEN_URL). |
| `EZAUTH_OAUTH2_<NAME>_ID_FIELD`      | JSON field name for the user ID in the userinfo response.         | `id`    |
| `EZAUTH_OAUTH2_<NAME>_EMAIL_FIELD`   | JSON field name for the email in the userinfo response.           | `email` |
