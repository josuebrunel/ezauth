# Standalone Service

Running `ezauth` as a standalone service allows you to offload authentication logic from your main application. It exposes a RESTful API that your frontend or other microservices can interact with.

## Building and Running

1.  **Download Binary (Recommended)**:
    Download the latest release for your platform from [GitHub Releases](https://github.com/josuebrunel/ezauth/releases).

2.  **Build from Source**:
    If you prefer to build from source:
    ```bash
    git clone https://github.com/josuebrunel/ezauth.git
    cd ezauth
    go build -o ezauthapi ./cmd/ezauthapi
    ```

3.  **Configure**:
    Create a `.env` file or set environment variables. See [Configuration](./configuration.md) for all available options.
    ```bash
    cp example.env .env
    # Edit .env with your settings
    ```

4.  **Run Migrations**:
    The `ezauthapi` binary itself runs migrations — no separate tool or building from source needed. `ezauthapi` (no arguments, see step 5) already does this automatically on every startup, but you can also run it as its own step, e.g. as a distinct stage in a deploy pipeline:
    ```bash
    ./ezauthapi migrate up
    ```
    `./ezauthapi migrate down` rolls back every migration (back to an empty schema); `./ezauthapi migrate revert` rolls back only the single most recently applied one.

    `-dialect`/`-dsn`/`-schema` flags (placed after the action) override the corresponding `EZAUTH_DB_*` env vars for that one invocation — useful for targeting a different database without changing your environment, e.g. `./ezauthapi migrate up -dsn="postgres://.../other_db"`.

5.  **Start the Service**:
    ```bash
    ./ezauthapi
    ```

6.  **Create an Admin User** (optional):
    Bootstraps a user (creating it if it doesn't already exist) and grants it an RBAC role — by default `admin` — so it passes `RequireRole("admin")`-gated routes. Safe to run more than once; re-running with the same email just ensures the role is granted.
    ```bash
    ./ezauthapi create-admin -email=admin@example.com -password=<a-strong-password>
    ```
    Use `-role=<name>` to grant a different role instead of the default `admin`.

## Using Docker

You can also use the provided `docker-compose.yaml` to run `ezauth` along with a PostgreSQL database.

```bash
docker-compose up -d
```

## Integrating with your Application

**Important**: All requests to the `ezauth` API (except OAuth2 callbacks) must include the `X-API-Key` header with the configured API key.

Once `ezauth` is running, your application can:

1.  **Direct Users to Login/Register**: Your frontend can send `POST` requests to `ezauth`'s `/auth/login` or `/auth/register` endpoints.
2.  **Secure Your Routes**: Your main application should verify the JWT access tokens issued by `ezauth`. Since `ezauth` uses standard JWTs, you can use any JWT library to verify the signature (using `EZAUTH_JWT_SECRET`).
3.  **Retrieve User Info**: Send a `GET` request to `/auth/userinfo` with the `Authorization: Bearer <access_token>` header.
