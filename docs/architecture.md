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
- User authentication and hashing.
- Token generation and validation (JWT and Refresh Tokens).
- Password reset and passwordless flows.
- Interaction with the Mailer.

### `Handler` (HTTP Layer)
The `handler` package (located in `pkg/handler/`) defines the RESTful API. It uses the `service` package to perform actions. It is responsible for:
- Routing requests (using `chi`).
- Parsing and validating request bodies.
- Enforcing authentication via middleware.
- Formatting JSON responses.

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

- **Mailer**: You can provide your own implementation of the `Mailer` interface if you need to use a service other than SMTP (e.g., SendGrid, Mailgun).
- **Custom Router**: You can pass your own `chi.Router` to the `Handler` if you want to add global middlewares or customize the routing behavior.
