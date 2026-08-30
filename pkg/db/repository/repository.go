// Package repository provides the data access layer for ezauth.
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/db/repository/mysql"
	"github.com/josuebrunel/ezauth/pkg/db/repository/postgres"
	"github.com/josuebrunel/ezauth/pkg/db/repository/sqlite"
	"github.com/josuebrunel/gopkg/xlog"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/scan"
)

const (
	DialectPSQL   = "postgres"
	DialectSqlite = "sqlite"
	DialectMysql  = "mysql"
)

type UserQuerier interface {
	QueryUserInsert(ctx context.Context, user *models.User) bob.Query
	QueryUserGetByEmail(ctx context.Context, email string) bob.Query
	QueryUserGetByUsername(ctx context.Context, username string) bob.Query
	QueryUserGetByPhone(ctx context.Context, phone string) bob.Query
	QueryUserGetByID(ctx context.Context, id string) bob.Query
	QueryUserGetByProvider(ctx context.Context, provider, providerID string) bob.Query
	QueryUserUpdate(ctx context.Context, user *models.User) bob.Query
	QueryUserDelete(ctx context.Context, id string) bob.Query
}

type TokenQuerier interface {
	QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query
	QueryTokenGetByID(ctx context.Context, id string) bob.Query
	QueryTokenGetByToken(ctx context.Context, token string) bob.Query
	QueryTokenListByUserIDAndType(ctx context.Context, userID, tokenType string) bob.Query
	QueryTokenRevoke(ctx context.Context, id string) bob.Query
	QueryTokenRevokeAllByUserID(ctx context.Context, userID string) bob.Query
	QueryTokenDelete(ctx context.Context, id string) bob.Query
}

type WebauthnCredentialQuerier interface {
	QueryWebauthnCredentialInsert(ctx context.Context, cred *models.WebauthnCredential) bob.Query
	QueryWebauthnCredentialGetByID(ctx context.Context, id string) bob.Query
	QueryWebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) bob.Query
	QueryWebauthnCredentialListByUserID(ctx context.Context, userID string) bob.Query
	QueryWebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) bob.Query
	QueryWebauthnCredentialDelete(ctx context.Context, id string) bob.Query
}

type WebauthnChallengeQuerier interface {
	QueryWebauthnChallengeInsert(ctx context.Context, ch *models.WebauthnChallenge) bob.Query
	QueryWebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) bob.Query
	QueryWebauthnChallengeDelete(ctx context.Context, id string) bob.Query
}

type Querier interface {
	UserQuerier
	TokenQuerier
	WebauthnCredentialQuerier
	WebauthnChallengeQuerier
}

// Opts defines the options for opening a repository connection.
type Opts struct {
	Dialect string
	DSN     string
	Schema  string
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

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create user", "error", err, "email", user.Email)
			return nil, err
		}
		return r.UserGetByID(ctx, user.ID)
	}

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

// UserGetByUsername retrieves a user by their username.
func (r Repository) UserGetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := r.QueryUserGetByUsername(ctx, username)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by username", "error", err, "username", username)
		return nil, err
	}
	return user, nil
}

// UserGetByPhone retrieves a user by their phone number.
func (r Repository) UserGetByPhone(ctx context.Context, phone string) (*models.User, error) {
	query := r.QueryUserGetByPhone(ctx, phone)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by phone", "error", err)
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

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to update user", "error", err, "email", user.Email)
			return nil, err
		}
		return r.UserGetByID(ctx, user.ID)
	}

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

// TokenCreate creates a new refresh token or password reset token in the database.
func (r Repository) TokenCreate(ctx context.Context, token *models.Token) (*models.Token, error) {
	query := r.QueryTokenInsert(ctx, token)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create token", "error", err)
			return nil, err
		}
		// Since we generate ID in Go, we can use it to fetch
		return r.TokenGetByID(ctx, token.ID)
	}

	createdToken, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to create token", "error", err)
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
		xlog.Error("Failed to get token by token", "error", err)
		return nil, err
	}
	return token, nil
}

// TokenListByUserIDAndType lists all non-revoked tokens of a given type for a user
// (e.g. trusted devices).
func (r Repository) TokenListByUserIDAndType(ctx context.Context, userID, tokenType string) ([]*models.Token, error) {
	query := r.QueryTokenListByUserIDAndType(ctx, userID, tokenType)
	tokens, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to list tokens by user and type", "error", err, "user_id", userID, "token_type", tokenType)
		return nil, err
	}
	return tokens, nil
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

// TokenRevokeAllByUserID revokes all non-revoked tokens for a given user.
func (r Repository) TokenRevokeAllByUserID(ctx context.Context, userID string) error {
	query := r.QueryTokenRevokeAllByUserID(ctx, userID)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke all tokens for user", "error", err, "user_id", userID)
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

// WebauthnCredentialCreate creates a new WebAuthn credential record.
func (r Repository) WebauthnCredentialCreate(ctx context.Context, cred *models.WebauthnCredential) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialInsert(ctx, cred)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create webauthn credential", "error", err, "user_id", cred.UserID)
			return nil, err
		}
		return r.WebauthnCredentialGetByID(ctx, cred.ID)
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to create webauthn credential", "error", err, "user_id", cred.UserID)
		return nil, err
	}
	return created, nil
}

// WebauthnCredentialGetByID retrieves a WebAuthn credential by its record ID.
func (r Repository) WebauthnCredentialGetByID(ctx context.Context, id string) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialGetByID(ctx, id)
	cred, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to get webauthn credential by id", "error", err, "id", id)
		return nil, err
	}
	return cred, nil
}

// WebauthnCredentialGetByCredentialID retrieves a WebAuthn credential by its (base64url-encoded) credential ID.
func (r Repository) WebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialGetByCredentialID(ctx, credentialID)
	cred, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to get webauthn credential by credential id", "error", err)
		return nil, err
	}
	return cred, nil
}

// WebauthnCredentialListByUserID lists all WebAuthn credentials belonging to a user.
func (r Repository) WebauthnCredentialListByUserID(ctx context.Context, userID string) ([]*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialListByUserID(ctx, userID)
	creds, err := bob.All(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to list webauthn credentials", "error", err, "user_id", userID)
		return nil, err
	}
	return creds, nil
}

// WebauthnCredentialUpdate updates a WebAuthn credential (e.g. sign count after a login).
func (r Repository) WebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) (*models.WebauthnCredential, error) {
	query := r.QueryWebauthnCredentialUpdate(ctx, cred)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to update webauthn credential", "error", err, "id", cred.ID)
			return nil, err
		}
		return r.WebauthnCredentialGetByID(ctx, cred.ID)
	}

	updated, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnCredential]())
	if err != nil {
		xlog.Error("Failed to update webauthn credential", "error", err, "id", cred.ID)
		return nil, err
	}
	return updated, nil
}

// WebauthnCredentialDelete deletes a WebAuthn credential.
func (r Repository) WebauthnCredentialDelete(ctx context.Context, id string) error {
	query := r.QueryWebauthnCredentialDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete webauthn credential", "error", err, "id", id)
		return err
	}
	return nil
}

// WebauthnChallengeCreate persists a WebAuthn ceremony's SessionData.
func (r Repository) WebauthnChallengeCreate(ctx context.Context, ch *models.WebauthnChallenge) (*models.WebauthnChallenge, error) {
	query := r.QueryWebauthnChallengeInsert(ctx, ch)

	if r.Opts.Dialect == DialectMysql {
		if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
			xlog.Error("Failed to create webauthn challenge", "error", err)
			return nil, err
		}
		return r.WebauthnChallengeGetBySessionKey(ctx, ch.SessionKey)
	}

	created, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnChallenge]())
	if err != nil {
		xlog.Error("Failed to create webauthn challenge", "error", err)
		return nil, err
	}
	return created, nil
}

// WebauthnChallengeGetBySessionKey retrieves a WebAuthn ceremony challenge by its opaque session key.
func (r Repository) WebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) (*models.WebauthnChallenge, error) {
	query := r.QueryWebauthnChallengeGetBySessionKey(ctx, sessionKey)
	ch, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.WebauthnChallenge]())
	if err != nil {
		xlog.Error("Failed to get webauthn challenge by session key", "error", err)
		return nil, err
	}
	return ch, nil
}

// WebauthnChallengeDelete deletes a WebAuthn ceremony challenge, e.g. after it has been consumed.
func (r Repository) WebauthnChallengeDelete(ctx context.Context, id string) error {
	query := r.QueryWebauthnChallengeDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete webauthn challenge", "error", err, "id", id)
		return err
	}
	return nil
}

func getDialectQuery(dbDialect string) Querier {
	switch dbDialect {
	case "postgres":
		return &postgres.PSQLQuerier{}
	case "mysql":
		return &mysql.MysqlQuerier{}
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
		if err == nil && opts.Schema != "" {
			for _, c := range opts.Schema {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
					return nil, fmt.Errorf("invalid schema name %q: only alphanumeric and underscore characters are allowed", opts.Schema)
				}
			}
			if _, err := db.Exec("CREATE SCHEMA IF NOT EXISTS " + opts.Schema); err != nil {
				xlog.Error("failed to create schema", "error", err, "schema", opts.Schema)
				return nil, err
			}
			if _, err := db.Exec("SET search_path TO " + opts.Schema); err != nil {
				xlog.Error("failed to set search_path", "error", err, "schema", opts.Schema)
				return nil, err
			}
		}
	case DialectMysql:
		db, err = mysql.GetDBConnection(opts.DSN)
		opts.Dialect = DialectMysql
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
