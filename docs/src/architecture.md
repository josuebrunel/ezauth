# Architecture

`ezauth` is built with a modular architecture that separates concerns between configuration, data persistence, business logic, and the HTTP layer.

## Component Overview

### `EzAuth` (The Library Entry Point)
The `EzAuth` struct (defined in `ezauth.go`) is the primary way to interact with the library. It orchestrates the other components and provides a simplified API for common tasks.

```go
type EzAuth struct {
    Config  *config.Config
    Repo    *repository.Repository
    Service *service.Auth
    Handler *handler.Handler
}
```

### `Service` (Business Logic)

The `service` package (located in `pkg/service/`) contains the core authentication logic. It is independent of the HTTP layer. This is where you'll find logic for:

* User authentication and hashing, including account lockout after repeated failed attempts.
* Token generation and validation (JWT and Refresh Tokens).
* Password reset and passwordless flows.
* Multi-Factor Authentication (TOTP), WebAuthn/Passkeys, and SMS OTP.
* Refresh-token reuse detection: revokes an entire session family when an already-rotated-out token is replayed.
* Admin impersonation, invitation-based onboarding, guarded email change, and admin user management.
* RBAC (roles/permissions), organizations (lightweight multi-tenancy), and scoped API keys.
* Interaction with the Mailer and, for SMS OTP, the `SMSSender`.
* Dispatching lifecycle events to the `Hook` interface (see [Hooks](./guides/admin-operations.md#hooks)).

### `Handler` (HTTP Layer)
The `handler` package (located in `pkg/handler/`) defines the RESTful API. It uses the `service` package to perform actions. It is responsible for:

* Routing requests (using `chi`).
* Parsing and validating request bodies.
* Enforcing authentication via middleware.
* Formatting JSON responses.

### `Repository` (Data Persistence)
The `repository` package (located in `pkg/db/repository/`) handles all database interactions. It uses `bob` as a query builder and supports multiple database dialects.

### `Config` (Configuration)
The `config` package (located in `pkg/config/`) handles loading configuration from environment variables.

## Data Flow

1.  **Incoming Request**: An HTTP request arrives at the `Handler`.
2.  **Routing & Middleware**: The `Handler` routes the request to the appropriate function. If the route is protected, the `AuthMiddleware` validates the JWT.
3.  **Service Call**: The `Handler` parses the request body and calls a method on the `Service`.
4.  **Database Interaction**: The `Service` performs business logic and interacts with the `Repository` to read or write data.
5.  **Response**: The `Service` returns a result to the `Handler`, which then sends a JSON response back to the client.

## Extension Points

* **Mailer**: You can provide your own implementation of the `Mailer` interface if you need to use a service other than SMTP (e.g., SendGrid, Mailgun).
* **SMSSender**: You can provide your own implementation of the `SMSSender` interface to deliver SMS OTP codes through your provider of choice (e.g., Twilio, SNS).
* **Hooks**: Implement the `Hook` interface (or embed `service.DefaultHook` and override only what you need) to intercept before/after lifecycle events — user creation/update/deletion, sign-in/sign-out, password reset, OAuth2, MFA enable/disable, and impersonation start/end. See [Hooks](./guides/admin-operations.md#hooks) for the full list and usage.
* **Custom Router**: You can pass your own `chi.Router` to the `Handler` if you want to add global middlewares or customize the routing behavior.
