package ezauth

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
	"github.com/josuebrunel/ezauth/pkg/handler"
	"github.com/josuebrunel/ezauth/pkg/service"
)

type EzAuth struct {
	Config  *config.Config
	Repo    *repository.Repository
	Service *service.Auth
	Handler *handler.Handler
}

// New creates a new EzAuth instance from a config. It handles database connection.
func New(cfg *config.Config, path string) (*EzAuth, error) {
	repo, err := repository.Open(repository.Opts{
		Dialect: cfg.DB.Dialect,
		DSN:     cfg.DB.DSN,
	})
	if err != nil {
		return nil, err
	}

	svc := service.New(cfg, repo)
	h := handler.New(svc, path)

	return &EzAuth{
		Config:  cfg,
		Repo:    repo,
		Service: svc,
		Handler: h,
	}, nil
}

// NewWithDB creates a new EzAuth instance using an existing database connection.
func NewWithDB(cfg *config.Config, db *sql.DB, path string) (*EzAuth, error) {
	repo := repository.New(db, cfg.DB.Dialect)
	svc := service.New(cfg, repo)
	h := handler.New(svc, path)

	return &EzAuth{
		Config:  cfg,
		Repo:    repo,
		Service: svc,
		Handler: h,
	}, nil
}

// Migrate runs the database migrations.
func (e *EzAuth) Migrate() error {
	return migrations.MigrateUpWithDBConn(e.Repo.DB(), e.Repo.Opts.Dialect)
}

// AuthMiddleware returns the authentication middleware.
func (e *EzAuth) AuthMiddleware(next http.Handler) http.Handler {
	return e.Handler.AuthMiddleware(next)
}

// GetUserID retrieves the user ID from the request context.
func (e *EzAuth) GetUserID(ctx context.Context) (string, error) {
	return handler.GetUserID(ctx)
}
