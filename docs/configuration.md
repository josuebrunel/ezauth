# Configuration

`ezauth` is configured primarily through environment variables. All variables are prefixed with `EZAUTH_`.

## Global Settings

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `EZAUTH_ADDR` | The address the server listens on. | `:8080` |
| `EZAUTH_BASE_URL` | The base URL of the auth service (used for emails). | `http://localhost:8080` |
| `EZAUTH_DEBUG` | Enable debug logging. | `false` |
| `EZAUTH_SECRET` | Secret key used for various internal encryptions. | |
| `EZAUTH_JWT_SECRET` | Secret key used to sign JWT tokens. | |
| `EZAUTH_TIMEOUT` | Request timeout duration. | `30s` |

## Database Settings

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `EZAUTH_DB_DIALECT` | Database dialect (`sqlite3` or `postgres`). | `sqlite3` |
| `EZAUTH_DB_DSN` | Database connection string. | `ezauth.db` |

## SMTP Settings

Used for sending password reset and magic link emails.

| Variable | Description | Default |
| -------- | ----------- | ------- |
| `EZAUTH_SMTP_HOST` | SMTP server host. | |
| `EZAUTH_SMTP_PORT` | SMTP server port. | `587` |
| `EZAUTH_SMTP_USER` | SMTP username. | |
| `EZAUTH_SMTP_PASSWORD` | SMTP password. | |
| `EZAUTH_SMTP_FROM` | The email address to send from. | `noreply@example.com` |

## OAuth2 Settings

### General
| Variable | Description |
| -------- | ----------- |
| `EZAUTH_OAUTH2_CALLBACK_URL` | The URL users are redirected to after successful OAuth2 login. |

### Google
| Variable | Description |
| -------- | ----------- |
| `EZAUTH_OAUTH2_GOOGLE_CLIENT_ID` | Google OAuth2 Client ID. |
| `EZAUTH_OAUTH2_GOOGLE_CLIENT_SECRET` | Google OAuth2 Client Secret. |
| `EZAUTH_OAUTH2_GOOGLE_REDIRECT_URL` | Redirect URL registered in Google Console. |
| `EZAUTH_OAUTH2_GOOGLE_SCOPES` | Scopes to request (e.g., `email,profile`). |

### GitHub
| Variable | Description |
| -------- | ----------- |
| `EZAUTH_OAUTH2_GITHUB_CLIENT_ID` | GitHub OAuth2 Client ID. |
| `EZAUTH_OAUTH2_GITHUB_CLIENT_SECRET` | GitHub OAuth2 Client Secret. |
| `EZAUTH_OAUTH2_GITHUB_REDIRECT_URL` | Redirect URL registered in GitHub settings. |
| `EZAUTH_OAUTH2_GITHUB_SCOPES` | Scopes to request (e.g., `user:email`). |

### Facebook
| Variable | Description |
| -------- | ----------- |
| `EZAUTH_OAUTH2_FACEBOOK_CLIENT_ID` | Facebook OAuth2 Client ID. |
| `EZAUTH_OAUTH2_FACEBOOK_CLIENT_SECRET` | Facebook OAuth2 Client Secret. |
| `EZAUTH_OAUTH2_FACEBOOK_REDIRECT_URL` | Redirect URL registered in Facebook settings. |
| `EZAUTH_OAUTH2_FACEBOOK_SCOPES` | Scopes to request (e.g., `email`). |
