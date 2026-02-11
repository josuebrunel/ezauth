// Package ezauth provides a library and service for easy authentication in Go.
// It supports Email/Password, JWT sessions, and OAuth2 (Google, GitHub, Facebook).
package ezauth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
	"github.com/josuebrunel/ezauth/pkg/handler"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

// EzAuth represents the main entry point for the ezauth library.
// It encapsulates configuration, repository, service, and handler components.
type EzAuth struct {
	Config  *config.Config
	Repo    *repository.Repository
	Service *service.Auth
	Handler *handler.Handler
}

// New creates a new EzAuth instance from a config.
// It handles database connection based on the provided configuration.
// path is the base URL path where the authentication routes will be mounted (e.g., "auth").
func New(cfg *config.Config, path string) (*EzAuth, error) {
	repo, err := repository.Open(repository.Opts{
		Dialect: cfg.DB.Dialect,
		DSN:     cfg.DB.DSN,
	})
	if err != nil {
		return nil, err
	}

	svc := service.New(cfg, repo, path)
	h := handler.New(svc, path)

	if cfg.Debug {
		xlog.Setup(xlog.Config{Level: "DEBUG"})
	} else {
		xlog.Setup(xlog.Config{Level: "INFO"})
	}

	return &EzAuth{
		Config:  cfg,
		Repo:    repo,
		Service: svc,
		Handler: h,
	}, nil
}

// NewWithDB creates a new EzAuth instance using an existing database connection.
// path is the base URL path where the authentication routes will be mounted (e.g., "auth").
func NewWithDB(cfg *config.Config, db *sql.DB, path string) (*EzAuth, error) {
	repo := repository.New(db, cfg.DB.Dialect)
	svc := service.New(cfg, repo, path)
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

// GetSessionToken retrieves the session token from the request context.
func (e *EzAuth) GetSessionTokens(ctx context.Context) (map[string]string, error) {
	tokens, bool := e.Handler.GetSessionTokens(ctx)
	if !bool {
		return nil, errors.New("session tokens not found")
	}
	return tokens, nil
}

// GetSessionUser returns the authenticated user from the context or session.
func (e *EzAuth) GetSessionUser(ctx context.Context) (*models.User, error) {
	return e.Handler.GetSessionUser(ctx)
}

// LoadUserMiddleware returns the middleware that loads the user into the context.
func (e *EzAuth) LoadUserMiddleware(next http.Handler) http.Handler {
	return e.Handler.LoadUserMiddleware(next)
}

// LoginRequiredMiddleware returns the middleware that requires the request to be authenticated.
func (e *EzAuth) LoginRequiredMiddleware(next http.Handler) http.Handler {
	return e.Handler.LoginRequiredMiddleware(next)
}

// IsAuthenticated checks if the request is authenticated.
func (e *EzAuth) IsAuthenticated(ctx context.Context) bool {
	return e.Handler.IsAuthenticated(ctx)
}

// GetErrorMessage retrieves and clears any error flash message from the session.
// Flash messages are one-time messages set during form handling (e.g., login errors).
func (e *EzAuth) GetErrorMessage(ctx context.Context) string {
	return e.Handler.GetErrorMessage(ctx)
}

// GetSuccessMessage retrieves and clears any success flash message from the session.
// Flash messages are one-time messages set during form handling (e.g., password reset success).
func (e *EzAuth) GetSuccessMessage(ctx context.Context) string {
	return e.Handler.GetSuccessMessage(ctx)
}
