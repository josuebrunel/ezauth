# ezauth

`ezauth` is a simple and easy-to-use authentication library and service for Golang. It provides a robust set of features to handle user registration, login, session management, and more.

[![Tests](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml/badge.svg)](https://github.com/josuebrunel/ezauth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/josuebrunel/ezauth.svg)](https://pkg.go.dev/github.com/josuebrunel/ezauth)

## Features

- **Email/Password Authentication**: registration and login, with account lockout after repeated failed attempts.
- **JWT-based Sessions**: access and refresh tokens with rotation, plus automatic reuse/theft detection.
- **Sign-in methods**: OAuth2 (Google, GitHub, Facebook, Discord, GitLab, Slack, LinkedIn, Spotify, and custom/OIDC), magic links, WebAuthn/passkeys, and SMS OTP.
- **Account security**: TOTP MFA with trusted devices, session revocation ("log out other devices"), scoped API keys, guarded email changes.
- **Authorization**: real RBAC (roles/permissions tables) and lightweight multi-tenancy (organizations), fully additive alongside the legacy `User.Roles` field.
- **Admin & operations**: impersonation, invitation-based onboarding, user management, a persisted audit log, and extensible hooks.
- **Extended User Profiles**: username, name, locale, timezone, roles, and metadata.
- **Storage**: SQLite, PostgreSQL, and MySQL.
- **Integration**: embed as a Go library, or run as a standalone authentication service.

> [!IMPORTANT]
> `ezauth` performs no built-in authorization. Admin-facing features (impersonation, invitations, admin user management, RBAC/organization management) enforce no role checks themselves — your application is responsible for verifying the caller is allowed (e.g. `caller.HasRole("admin")`) before exposing them.

## Choose Your Path

`ezauth` can be used in two primary ways:

1.  **[Embed as a Library](./library.md)**: initialize `ezauth` inside your Go application and mount its routes and middlewares on your own router. The most flexible option.
2.  **[Run as a Standalone Service](./standalone.md)**: run `ezauth` as an independent service your frontend and microservices talk to over HTTP.

Not sure which to pick? Start with [Installation](./installation.md), then the [Configuration](./configuration.md) reference.

## Guides

| Guide | Covers |
| ----- | ------ |
| [Sessions, Middleware and Helpers](./guides/sessions-middleware-helpers.md) | Cookie sessions, retrieving the user, flash messages, CSRF, route-protection middlewares, helper functions. |
| [Sign-in Methods](./guides/sign-in-methods.md) | OAuth2 / OIDC providers, SMS OTP, WebAuthn / passkeys. |
| [Account Security](./guides/account-security.md) | MFA (TOTP) & trusted devices, session revocation, refresh-token reuse detection, account lockout, guarded email changes, asymmetric JWT signing (JWKS), scoped API keys. |
| [Admin and Operations](./guides/admin-operations.md) | Impersonation, roles & permissions (RBAC), organizations (multi-tenancy), invitations, admin user management, audit log, hooks. |

## Reference

- [API Endpoints](./api-endpoints.md): every form and JSON endpoint.
- [Architecture](./architecture.md): how `EzAuth`, `Handler`, and `Service` fit together.
- [Handler](./references/handler.md), [Middleware](./references/middleware.md), [Service](./references/service.md), [Repository](./references/repository.md): the Go API surface.

## Examples

- [Go Server](./examples/go-server.md): a complete `chi` integration.
- [Javascript Client](./examples/javascript-client.md): interacting with the API from a browser.
