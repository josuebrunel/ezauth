package repository

import (
	"context"
	"database/sql"
	"os"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/db/repository/postgres"
	"github.com/josuebrunel/ezauth/pkg/db/repository/sqlite"
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

type Repository struct {
	db bob.DB
	IQueryAdapter
}

func New(db *sql.DB) *Repository {
	qAdapter := getDialectQuery()

	return &Repository{
		db:            bob.NewDB(db),
		IQueryAdapter: qAdapter,
	}

}

func getDialectQuery() IQueryAdapter {
	dbDialect := os.Getenv("APP_DB_DIALECT")
	switch dbDialect {
	case "postgres":
		return &postgres.PSQLQueryAdapter{}
	case "sqlite":
		return &sqlite.SqliteQueryAdapter{}
	default:
		return &postgres.PSQLQueryAdapter{}
	}
}

func (r *Repository) Close() error {
	return r.db.Close()
}

func (r Repository) UserCreate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserInsert(ctx, user)
	user, err := bob.One(ctx, r.db, query, scan.StructMapper[*models.User]())
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r Repository) UserGetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := r.QueryUserGetByEmail(ctx, email)
	user, err := bob.One(ctx, r.db, query, scan.StructMapper[*models.User]())
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r Repository) UserGetByID(ctx context.Context, id string) (*models.User, error) {
	query := r.QueryUserGetByID(ctx, id)
	user, err := bob.One(ctx, r.db, query, scan.StructMapper[*models.User]())
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r Repository) UserUpdate(ctx context.Context, user *models.User) (*models.User, error) {
	query := r.QueryUserUpdate(ctx, user)
	user, err := bob.One(ctx, r.db, query, scan.StructMapper[*models.User]())
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r Repository) UserDelete(ctx context.Context, id string) error {
	query := r.QueryUserDelete(ctx, id)
	_, err := bob.Exec(ctx, r.db, query)
	return err
}

func (r Repository) TokenCreate(ctx context.Context, token *models.Token) (*models.Token, error) {
	query := r.QueryTokenInsert(ctx, token)
	token, err := bob.One(ctx, r.db, query, scan.StructMapper[*models.Token]())
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (r Repository) TokenGetByID(ctx context.Context, id string) (*models.Token, error) {
	query := r.QueryTokenGetByID(ctx, id)
	token, err := bob.One(ctx, r.db, query, scan.StructMapper[*models.Token]())
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (r Repository) TokenGetByToken(ctx context.Context, tokenValue string) (*models.Token, error) {
	query := r.QueryTokenGetByToken(ctx, tokenValue)
	token, err := bob.One(ctx, r.db, query, scan.StructMapper[*models.Token]())
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (r Repository) TokenDelete(ctx context.Context, id string) error {
	query := r.QueryTokenDelete(ctx, id)
	_, err := bob.Exec(ctx, r.db, query)
	return err
}
