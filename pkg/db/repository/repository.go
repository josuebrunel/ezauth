// Package repository provides the data access layer for ezauth.
package repository

import (
	"context"
	"database/sql"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/db/repository/postgres"
	"github.com/josuebrunel/ezauth/pkg/db/repository/sqlite"
	"github.com/josuebrunel/gopkg/xlog"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/scan"
)

const (
	DialectPSQL   = "postgres"
	DialectSqlite = "sqlite3"
)

type UserQuerier interface {
	QueryUserInsert(ctx context.Context, user *models.User) bob.Query
	QueryUserGetByEmail(ctx context.Context, email string) bob.Query
	QueryUserGetByID(ctx context.Context, id string) bob.Query
	QueryUserGetByProvider(ctx context.Context, provider, providerID string) bob.Query
	QueryUserUpdate(ctx context.Context, user *models.User) bob.Query
	QueryUserDelete(ctx context.Context, id string) bob.Query
}

type TokenQuerier interface {
	QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query
	QueryTokenGetByID(ctx context.Context, id string) bob.Query
	QueryTokenGetByToken(ctx context.Context, token string) bob.Query
	QueryTokenRevoke(ctx context.Context, id string) bob.Query
	QueryTokenDelete(ctx context.Context, id string) bob.Query
}

type PasswordlessQuerier interface {
	QueryPasswordlessTokenInsert(ctx context.Context, token *models.PasswordlessToken) bob.Query
	QueryPasswordlessTokenGetByToken(ctx context.Context, token string) bob.Query
	QueryPasswordlessTokenDelete(ctx context.Context, token string) bob.Query
}

type Querier interface {
	UserQuerier
	TokenQuerier
	PasswordlessQuerier
}

// Opts defines the options for opening a repository connection.
type Opts struct {
	Dialect string
	DSN     string
}

// Repository handles all database operations.
type Repository struct {
	Opts Opts
	bdb  bob.DB
	db   *sql.DB
	Querier
}

// New creates a new Repository with the given database connection and dialect.
func New(db *sql.DB, dialect string) *Repository {
	querier := getDialectQuery(dialect)
	bdb := bob.NewDB(db)

	return &Repository{
		db:      db,
		bdb:     bdb,
		Querier: querier,
		Opts:    Opts{Dialect: dialect},
	}
}

// Open opens a new database connection and returns a Repository.
func Open(opts Opts) (*Repository, error) {
	db, err := getDBConnection(opts)
	if err != nil {
		return nil, err
	}
	return New(db, opts.Dialect), nil
}

// DB returns the underlying sql.DB connection.
func (r Repository) DB() *sql.DB {
	return r.db
}

// Ping pings the database to check if the connection is alive.
func (r *Repository) Ping() error {
	return r.bdb.Ping()
}

// Close closes the database connection.
func (r *Repository) Close() error {
	return r.bdb.Close()
}

// UserCreate creates a new user in the database.
func (r Repository) UserCreate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserInsert(ctx, user)
	createdUser, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to create user", "error", err, "email", user.Email)
		return nil, err
	}
	return createdUser, nil
}

// UserGetByProvider retrieves a user by their OAuth2 provider and provider ID.
func (r Repository) UserGetByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	query := r.QueryUserGetByProvider(ctx, provider, providerID)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by provider", "error", err, "provider", provider, "provider_id", providerID)
		return nil, err
	}
	return user, nil
}

// UserGetByEmail retrieves a user by their email address.
func (r Repository) UserGetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := r.QueryUserGetByEmail(ctx, email)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by email", "error", err, "email", email)
		return nil, err
	}
	return user, nil
}

// UserGetByID retrieves a user by their ID.
func (r Repository) UserGetByID(ctx context.Context, id string) (*models.User, error) {
	query := r.QueryUserGetByID(ctx, id)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by id", "error", err, "id", id)
		return nil, err
	}
	return user, nil
}

// UserUpdate updates an existing user in the database.
func (r Repository) UserUpdate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserUpdate(ctx, user)
	updatedUser, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to update user", "error", err, "email", user.Email)
		return nil, err
	}
	return updatedUser, nil
}

// UserDelete deletes a user from the database.
func (r Repository) UserDelete(ctx context.Context, id string) error {
	query := r.QueryUserDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete user", "error", err, "id", id)
		return err
	}
	return nil
}

// PasswordlessTokenCreate creates a new passwordless token in the database.
func (r Repository) PasswordlessTokenCreate(ctx context.Context, token *models.PasswordlessToken) (*models.PasswordlessToken, error) {
	query := r.QueryPasswordlessTokenInsert(ctx, token)
	createdToken, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.PasswordlessToken]())
	if err != nil {
		xlog.Error("Failed to create passwordless token", "error", err, "email", token.Email)
		return nil, err
	}
	return createdToken, nil
}

// PasswordlessTokenGetByToken retrieves a passwordless token by its token value.
func (r Repository) PasswordlessTokenGetByToken(ctx context.Context, tokenValue string) (*models.PasswordlessToken, error) {
	query := r.QueryPasswordlessTokenGetByToken(ctx, tokenValue)
	token, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.PasswordlessToken]())
	if err != nil {
		xlog.Error("Failed to get passwordless token by token", "error", err, "token", tokenValue)
		return nil, err
	}
	return token, nil
}

// PasswordlessTokenDelete deletes a passwordless token from the database.
func (r Repository) PasswordlessTokenDelete(ctx context.Context, tokenValue string) error {
	query := r.QueryPasswordlessTokenDelete(ctx, tokenValue)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete passwordless token", "error", err, "token", tokenValue)
		return err
	}
	return nil
}

// TokenCreate creates a new refresh token or password reset token in the database.
func (r Repository) TokenCreate(ctx context.Context, token *models.Token) (*models.Token, error) {
	query := r.QueryTokenInsert(ctx, token)
	createdToken, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to create token", "error", err, "token", token.Token)
		return nil, err
	}
	return createdToken, nil
}

// TokenGetByID retrieves a token by its ID.
func (r Repository) TokenGetByID(ctx context.Context, id string) (*models.Token, error) {
	query := r.QueryTokenGetByID(ctx, id)
	token, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to get token by id", "error", err, "id", id)
		return nil, err
	}
	return token, nil
}

// TokenGetByToken retrieves a token by its token value.
func (r Repository) TokenGetByToken(ctx context.Context, tokenValue string) (*models.Token, error) {
	query := r.QueryTokenGetByToken(ctx, tokenValue)
	token, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to get token by token", "error", err, "token", tokenValue)
		return nil, err
	}
	return token, nil
}

// TokenRevoke marks a token as revoked in the database.
func (r Repository) TokenRevoke(ctx context.Context, id string) error {
	query := r.QueryTokenRevoke(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke token", "error", err, "id", id)
		return err
	}
	return nil
}

// TokenDelete deletes a token from the database.
func (r Repository) TokenDelete(ctx context.Context, id string) error {
	query := r.QueryTokenDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete token", "error", err, "id", id)
		return err
	}
	return nil
}

func getDialectQuery(dbDialect string) Querier {
	switch dbDialect {
	case "postgres":
		return &postgres.PSQLQuerier{}
	case "sqlite", "sqlite3":
		return &sqlite.SqliteQuerier{}
	default:
		return &sqlite.SqliteQuerier{}
	}
}

func getDBConnection(opts Opts) (*sql.DB, error) {
	var (
		db  *sql.DB
		err error
	)

	switch opts.Dialect {
	case DialectPSQL:
		db, err = postgres.GetDBConnection(opts.DSN)
		opts.Dialect = DialectPSQL
	default:
		db, err = sqlite.GetDBConnection(opts.DSN)
		opts.Dialect = DialectSqlite
	}

	if err != nil {
		xlog.Error("failed to open connection", "error", err, "dsn", opts.DSN)
		return nil, err
	}

	if err := db.Ping(); err != nil {
		xlog.Error("failed to ping database", "error", err)
		return nil, err
	}

	return db, nil
}
