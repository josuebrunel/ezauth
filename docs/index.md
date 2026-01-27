# ezauth

`ezauth` is a simple and easy-to-use authentication library and service for Golang. It provides a robust set of features to handle user registration, login, session management, and more.

## Features

- **Email/Password Authentication**: Secure user registration and login.
- **JWT-based Sessions**: Access and Refresh tokens with rotation for enhanced security.
- **OAuth2 Support**: Built-in support for Google, GitHub, and Facebook.
- **Password Reset & Passwordless**: Magic link and password reset flows.
- **Extended User Profiles**: Store additional user information like name, locale, timezone, and roles.
- **Multi-Database Support**: Support for SQLite and PostgreSQL.
- **Flexible Integration**: Use it as a standalone service or embed it as a library.

## Getting Started

`ezauth` can be used in two primary ways:

1.  **[Standalone Service](./standalone.md)**: Run `ezauth` as an independent authentication service.
2.  **[Library](./library.md)**: Embed `ezauth` directly into your Go application.

## Documentation Sections

- **[Installation](./installation.md)**: How to get `ezauth`.
- **[Configuration](./configuration.md)**: Details on all environment variables.
- **[API Endpoints](./api-endpoints.md)**: Comprehensive API reference.
- **[Architecture](./architecture.md)**: Understanding `EzAuth`, `Handler`, and `Service`.
