// Package ezauth provides a library and service for easy authentication in Go.
// It supports Email/Password, JWT sessions, and OAuth2 (Google, GitHub, Facebook).
package ezauth

import (
	"context"
	"database/sql"
	"errors"
	"html/template"
	"net/http"

	csrf "filippo.io/csrf/gorilla"
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

// GetSessionTokens retrieves the session token from the request context.
func (e *EzAuth) GetSessionTokens(ctx context.Context) (map[string]string, error) {
	tokens, ok := e.Handler.GetSessionTokens(ctx)
	if !ok {
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

// SessionMiddleware returns the middleware that handles session management and user loading.
func (e *EzAuth) SessionMiddleware(next http.Handler) http.Handler {
	return e.Handler.SessionMiddleware(next)
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

// GetUserID retrieves the user ID from the request context.
// It requires AuthMiddleware, LoadUserMiddleware, or SessionMiddleware to be used.
// It returns an error if the user ID is not found in the context.
func GetUserID(ctx context.Context) (string, error) {
	return handler.GetUserID(ctx)
}

// GetUser retrieves the authenticated user from the context.
// It requires LoadUserMiddleware or SessionMiddleware to be used.
func GetUser(ctx context.Context) (*models.User, error) {
	return handler.GetSessionUser(ctx)
}

// IsAuthenticated checks if the request is authenticated.
// It returns true if a user object or user ID is found in the context.
// It requires AuthMiddleware, LoadUserMiddleware, or SessionMiddleware to be used.
func IsAuthenticated(ctx context.Context) bool {
	if _, err := GetUser(ctx); err == nil {
		return true
	}
	if _, err := GetUserID(ctx); err == nil {
		return true
	}
	return false
}

// CSRFToken returns the current CSRF token string from the request context.
// This requires the csrf.Protect middleware to have run before this request.
func CSRFToken(r *http.Request) string {
	return csrf.Token(r)
}

// CSRFTemplateField is a template helper that returns an HTML hidden input field
// containing the CSRF token. This requires the csrf.Protect middleware to have run.
func CSRFTemplateField(r *http.Request) template.HTML {
	return csrf.TemplateField(r)
}
