# Standalone Service

Running `ezauth` as a standalone service allows you to offload authentication logic from your main application. It exposes a RESTful API that your frontend or other microservices can interact with.

## Building and Running

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/josuebrunel/ezauth.git
    cd ezauth
    ```

2.  **Configure**:
    Create a `.env` file or set environment variables. See [Configuration](./configuration.md) for all available options.
    ```bash
    cp example.env .env
    # Edit .env with your settings
    ```

3.  **Build**:
    ```bash
    go build -o ezauthapi ./cmd/ezauthapi
    ```

4.  **Run Migrations**:
    `ezauth` can automatically run migrations on startup when used as a library, but for the standalone service, you can run them manually or ensure they are run by the binary.
    ```bash
    go build -o migrate ./cmd/migrate
    ./migrate up
    ```

5.  **Start the Service**:
    ```bash
    ./ezauthapi
    ```

## Using Docker

You can also use the provided `docker-compose.yaml` to run `ezauth` along with a PostgreSQL database.

```bash
docker-compose up -d
```

## Integrating with your Application

Once `ezauth` is running, your application can:
1.  **Direct Users to Login/Register**: Your frontend can send `POST` requests to `ezauth`'s `/auth/login` or `/auth/register` endpoints.
2.  **Secure Your Routes**: Your main application should verify the JWT access tokens issued by `ezauth`. Since `ezauth` uses standard JWTs, you can use any JWT library to verify the signature (using `EZAUTH_JWT_SECRET`).
3.  **Retrieve User Info**: Send a `GET` request to `/auth/userinfo` with the `Authorization: Bearer <access_token>` header.
