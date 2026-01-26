package repository

import (
	"context"
	"database/sql"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/db/repository/postgres"
	"github.com/josuebrunel/ezauth/pkg/db/repository/sqlite"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/scan"
)

const (
	DialectPSQL   = "postgres"
	DialectSqlite = "sqlite"
)

type IQueryAdapterUser interface {
	QueryUserInsert(ctx context.Context, user *models.User) bob.Query
	QueryUserGetByEmail(ctx context.Context, email string) bob.Query
	QueryUserGetByID(ctx context.Context, id string) bob.Query
	QueryUserUpdate(ctx context.Context, user *models.User) bob.Query
	QueryUserDelete(ctx context.Context, id string) bob.Query
}

type IQueryAdapterToken interface {
	QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query
	QueryTokenGetByID(ctx context.Context, id string) bob.Query
	QueryTokenGetByToken(ctx context.Context, token string) bob.Query
	QueryTokenRevoke(ctx context.Context, id string) bob.Query
	QueryTokenDelete(ctx context.Context, id string) bob.Query
}

type IQueryAdapter interface {
	IQueryAdapterUser
	IQueryAdapterToken
}

type Opts struct {
	Dialect string
	DSN     string
}

type Repository struct {
	Opts Opts
	bdb  bob.DB
	db   *sql.DB
	IQueryAdapter
}

func New(opts Opts) *Repository {
	qAdapter := getDialectQuery(opts.Dialect)
	db := util.Must(getDBConnection(opts))
	bdb := bob.NewDB(db)

	return &Repository{
		db:            db,
		bdb:           bdb,
		IQueryAdapter: qAdapter,
	}
}

func (r Repository) DB() *sql.DB {
	return r.db
}

func (r *Repository) Ping() error {
	return r.bdb.Ping()
}

func (r *Repository) Close() error {
	return r.bdb.Close()
}

func (r Repository) UserCreate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserInsert(ctx, user)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to create user", "error", err)
		return nil, err
	}
	return user, nil
}

func (r Repository) UserGetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := r.QueryUserGetByEmail(ctx, email)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by email", "error", err, "email", user.Email)
		return nil, err
	}
	return user, nil
}

func (r Repository) UserGetByID(ctx context.Context, id string) (*models.User, error) {
	query := r.QueryUserGetByID(ctx, id)
	user, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to get user by id", "error", err, "id", id)
		return nil, err
	}
	return user, nil
}

func (r Repository) UserUpdate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserUpdate(ctx, user)
	dbg := bob.Debug(r.bdb)
	user, err := bob.One(ctx, dbg, query, scan.StructMapper[*models.User]())
	if err != nil {
		xlog.Error("Failed to update user", "error", err, "email", util.Deref(user).Email)
		return nil, err
	}
	return user, nil
}

func (r Repository) UserDelete(ctx context.Context, id string) error {
	query := r.QueryUserDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete user", "error", err, "id", id)
		return err
	}
	return nil
}

func (r Repository) TokenCreate(ctx context.Context, token *models.Token) (*models.Token, error) {
	query := r.QueryTokenInsert(ctx, token)
	tk, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to create token", "error", err, "token", token.Token)
		return nil, err
	}
	return tk, nil
}

func (r Repository) TokenGetByID(ctx context.Context, id string) (*models.Token, error) {
	query := r.QueryTokenGetByID(ctx, id)
	token, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to get token by id", "error", err, "id", id)
		return nil, err
	}
	return token, nil
}

func (r Repository) TokenGetByToken(ctx context.Context, tokenValue string) (*models.Token, error) {
	query := r.QueryTokenGetByToken(ctx, tokenValue)
	token, err := bob.One(ctx, r.bdb, query, scan.StructMapper[*models.Token]())
	if err != nil {
		xlog.Error("Failed to get token by token", "error", err, "token", tokenValue)
		return nil, err
	}
	return token, nil
}

func (r Repository) TokenRevoke(ctx context.Context, id string) error {
	query := r.QueryTokenRevoke(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to revoke token", "error", err, "id", id)
		return err
	}
	return nil
}

func (r Repository) TokenDelete(ctx context.Context, id string) error {
	query := r.QueryTokenDelete(ctx, id)
	if _, err := bob.Exec(ctx, r.bdb, query); err != nil {
		xlog.Error("Failed to delete token", "error", err, "id", id)
		return err
	}
	return nil
}

func getDialectQuery(dbDialect string) IQueryAdapter {
	switch dbDialect {
	case "postgres":
		return &postgres.PSQLQueryAdapter{}
	case "sqlite", "sqlite3":
		return &sqlite.SqliteQueryAdapter{}
	default:
		return &sqlite.SqliteQueryAdapter{}
	}
}

func getDBConnection(opts Opts) (*sql.DB, error) {
	var (
		db  *sql.DB
		err error
	)

	if opts.Dialect == DialectPSQL {
		db, err = sql.Open(opts.Dialect, opts.DSN)
	} else {
		db, err = sql.Open(opts.Dialect, opts.DSN)
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
