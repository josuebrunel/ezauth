# Configuration

`ezauth` is configured primarily through environment variables. All variables are prefixed with `EZAUTH_`.

## Global Settings

| Variable            | Description                                         | Default                 |
| ------------------- | --------------------------------------------------- | ----------------------- |
| `EZAUTH_ADDR`       | The address the server listens on.                  | `:8080`                 |
| `EZAUTH_API_KEY`    | Master API Key for protecting endpoints.            |                         |
| `EZAUTH_BASE_URL`   | The base URL of the auth service (used for emails). | `http://localhost:8080` |
| `EZAUTH_DEBUG`      | Enable debug logging.                               | `false`                 |
| `EZAUTH_JWT_SECRET` | Secret key used to sign JWT tokens.                 |                         |
| `EZAUTH_TIMEOUT`    | Request timeout duration.                           | `30s`                   |

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

## Form/Redirect Settings

Used for the Form-based handlers (browser flows).

| Variable                         | Description                                       | Default     |
| -------------------------------- | ------------------------------------------------- | ----------- |
| `EZAUTH_REDIRECT_AFTER_LOGIN`    | URL to redirect to after successful login.        | `/`         |
| `EZAUTH_REDIRECT_AFTER_REGISTER` | URL to redirect to after successful registration. | `/`         |
| `EZAUTH_LOGIN_PAGE_URL`          | URL of your custom Login page (for redirects).    | `/login`    |
| `EZAUTH_REGISTER_PAGE_URL`       | URL of your custom Register page (for redirects). | `/register` |

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
