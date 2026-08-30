# ezauth

`ezauth` is a simple and easy-to-use authentication library and service for Golang. It provides a robust set of features to handle user registration, login, session management, and more.

## Features

- **Email/Password Authentication**: Secure user registration and login, with account lockout after repeated failed attempts.
- **JWT-based Sessions**: Access and Refresh tokens with rotation for enhanced security.
- **OAuth2 Support**: Built-in support for Google, GitHub, Facebook, Discord, GitLab, Slack, LinkedIn, and Spotify, plus custom/OIDC provider registration.
- **Password Reset & Passwordless**: Magic link and password reset flows.
- **Multi-Factor Authentication**: TOTP-based MFA with step-up login, recovery codes, and "remember this device" trusted devices.
- **WebAuthn / Passkeys**: Passwordless registration and login via platform/roaming authenticators.
- **SMS OTP**: One-time codes over SMS for phone-based login/signup, via a pluggable `SMSSender` interface.
- **Admin Impersonation**: Admins can act as another user for support/debugging, then swap back to their own session.
- **Invitation-Based Onboarding**: Invite users by email with pre-verified addresses and pre-assigned roles.
- **Guarded Email Change**: Email changes require the current password and a confirmation link to the new address.
- **Admin User Management**: Search/filter/paginate users, suspend/reactivate accounts, and view auth history.
- **Extended User Profiles**: Store additional user information like username, name, locale, timezone, and roles.
- **Extensible Hooks**: Intercept before/after lifecycle events (user creation, sign-in, MFA, impersonation, and more).
- **Multi-Database Support**: Support for SQLite, PostgreSQL, and MySQL.
- **Flexible Integration**: Use it as a standalone service or embed it as a library.

> [!IMPORTANT]
> `ezauth` performs no built-in authorization. Admin-facing features (Impersonation, Invitations, Admin User Management) enforce no role checks themselves — your application is responsible for verifying the caller is allowed (e.g. `caller.HasRole("admin")`) before exposing them.

## Getting Started

`ezauth` can be used in two primary ways:

1.  **[Library](./library.md)**: Embed `ezauth` directly into your Go application. This is the primary, most flexible way to use `ezauth`.
2.  **[Standalone Service](./standalone.md)**: Run `ezauth` as an independent authentication service.

## Documentation Sections

- **[Installation](./installation.md)**: How to get `ezauth`.
- **[Configuration](./configuration.md)**: Details on all environment variables.
- **[API Endpoints](./api-endpoints.md)**: Comprehensive API reference.
- **[Architecture](./architecture.md)**: Understanding `EzAuth`, `Handler`, and `Service`.
