# Repository Reference

The `repository.Repository` struct handles all database interactions. It supports multiple SQL dialects (SQLite, PostgreSQL, MySQL) via `bob`.

```go
type Repository struct {
    // ...
}
```

## Constructor

### `Open`

Opens a database connection and returns a Repository instance.

```go
func Open(opts Opts) (*Repository, error)
```

### `New`

Creates a Repository from an existing `sql.DB` connection.

```go
func New(db *sql.DB, dialect string) *Repository
```

## User Methods

### `UserCreate`
Inserts a new user record.

```go
func (r Repository) UserCreate(ctx context.Context, user *models.User) (*models.User, error)
```

### `UserGetByEmail`
Retrieves a user by email.

```go
func (r Repository) UserGetByEmail(ctx context.Context, email string) (*models.User, error)
```

### `UserGetByID`
Retrieves a user by ID (UUID).

```go
func (r Repository) UserGetByID(ctx context.Context, id string) (*models.User, error)
```

### `UserGetByProvider`
Retrieves a user by OAuth2 provider ID.

```go
func (r Repository) UserGetByProvider(ctx context.Context, provider, providerID string) (*models.User, error)
```

### `UserUpdate`
Updates an existing user record.

```go
func (r Repository) UserUpdate(ctx context.Context, user *models.User) (*models.User, error)
```

### `UserDelete`
Deletes a user record.

```go
func (r Repository) UserDelete(ctx context.Context, id string) error
```

## Token Methods

### `TokenCreate`
Stores a new refresh token or other temporary token (reset, magic link).

```go
func (r Repository) TokenCreate(ctx context.Context, token *models.Token) (*models.Token, error)
```

### `TokenGetByToken`
Retrieves a token record by its value.

```go
func (r Repository) TokenGetByToken(ctx context.Context, tokenValue string) (*models.Token, error)
```

### `TokenRevoke`
Marks a token as revoked.

```go
func (r Repository) TokenRevoke(ctx context.Context, id string) error
```

### `TokenDelete`
Permanently deletes a token.

```go
func (r Repository) TokenDelete(ctx context.Context, id string) error
```
