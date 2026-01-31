# Service Reference

The `service.Auth` struct contains the core business logic for authentication. It is independent of the HTTP layer.

```go
type Auth struct {
    Cfg    *config.Config
    Repo   *repository.Repository
    Mailer Mailer
    // ...
}
```

## Constructor

### `New`

Creates a new `Auth` service.

```go
func New(cfg *config.Config, repo *repository.Repository, pathPrefix string) *Auth
```

### `NewFromConfig`

Creates a new `Auth` service and initializes the repository connection based on the config.

```go
func NewFromConfig(cfg *config.Config, pathPrefix string) (*Auth, error)
```

## User Operations

### `UserCreate`

Creates a new user. It hashes the password, validates the password length (min 8 chars), and stores the user in the repository.

```go
func (a *Auth) UserCreate(ctx context.Context, req *RequestBasicAuth) (*models.User, error)
```

### `UserAuthenticate`

Authenticates a user by email and password.

```go
func (a Auth) UserAuthenticate(ctx context.Context, req RequestBasicAuth) (*models.User, error)
```

### `UserUpdatePassword`

Updates a user's password. Enforces password validation rules.

```go
func (a Auth) UserUpdatePassword(ctx context.Context, user *models.User, password string) (*models.User, error)
```

### `UserUpdate`

Updates user profile information.

```go
func (a Auth) UserUpdate(ctx context.Context, user *models.User) (*models.User, error)
```

### `UserDelete`

Deletes a user by their ID.

```go
func (a Auth) UserDelete(ctx context.Context, id string) error
```

## Token Operations

### `TokenCreate`

Generates a new pair of Access Token (JWT) and Refresh Token (Opaque) for a user.

```go
func (a *Auth) TokenCreate(ctx context.Context, user *models.User) (*TokenResponse, error)
```

### `TokenRefresh`

Validates a refresh token and issues a new pair of tokens.

```go
func (a *Auth) TokenRefresh(ctx context.Context, refreshToken string) (*TokenResponse, error)
```

### `TokenRevoke`

Revokes a refresh token immediately.

```go
func (a *Auth) TokenRevoke(ctx context.Context, refreshToken string) error
```

## Password Flows

### `PasswordResetRequest`

Generates a reset token and sends it via email.

```go
func (a *Auth) PasswordResetRequest(ctx context.Context, req RequestPasswordReset) error
```

### `PasswordResetConfirm`

Verifies the reset token and updates the user's password.

```go
func (a *Auth) PasswordResetConfirm(ctx context.Context, req RequestPasswordResetConfirm) error
```

### `PasswordlessRequest`

Generates a magic link token and sends it via email.

```go
func (a *Auth) PasswordlessRequest(ctx context.Context, req service.RequestPasswordless) error
```

### `PasswordlessLogin`

Verifies the magic link token and issues authentication tokens.

```go
func (a *Auth) PasswordlessLogin(ctx context.Context, token string) (*TokenResponse, error)
```
