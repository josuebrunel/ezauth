// Package ezauth provides a library and service for easy authentication in Go.
// It supports Email/Password, JWT sessions, and OAuth2 (Google, GitHub, Facebook).
package ezauth

import (
	"context"
	"database/sql"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	csrf "filippo.io/csrf/gorilla"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
	"github.com/josuebrunel/ezauth/pkg/handler"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/service/providers"
	"github.com/josuebrunel/gopkg/xlog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
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

	auth := &EzAuth{
		Config:  cfg,
		Repo:    repo,
		Service: svc,
		Handler: h,
	}

	if err := auth.registerBuiltinProviders(context.Background()); err != nil {
		return nil, err
	}

	if err := auth.registerCustomProviders(context.Background()); err != nil {
		return nil, err
	}

	return auth, nil
}

// NewWithDB creates a new EzAuth instance using an existing database connection.
// path is the base URL path where the authentication routes will be mounted (e.g., "auth").
func NewWithDB(cfg *config.Config, db *sql.DB, path string) (*EzAuth, error) {
	repo := repository.New(db, cfg.DB.Dialect)
	svc := service.New(cfg, repo, path)
	h := handler.New(svc, path)

	auth := &EzAuth{
		Config:  cfg,
		Repo:    repo,
		Service: svc,
		Handler: h,
	}

	if err := auth.registerBuiltinProviders(context.Background()); err != nil {
		return nil, err
	}

	if err := auth.registerCustomProviders(context.Background()); err != nil {
		return nil, err
	}

	return auth, nil
}

// SetHook registers a Hook implementation to intercept auth lifecycle events.
// See service.Hook and service.DefaultHook for details.
func (e *EzAuth) SetHook(hook service.Hook) {
	e.Service.Hook = hook
}

// RegisterOAuth2Provider registers a custom OAuth2/OIDC provider on the service.
func (e *EzAuth) RegisterOAuth2Provider(name string, p service.OAuth2Provider) {
	e.Service.RegisterOAuth2Provider(name, p)
}

func (e *EzAuth) registerBuiltinProviders(ctx context.Context) error {
	// Pre-register all built-in OAuth2 providers from config.
	builtins := []struct {
		name   string
		config func() (service.OAuth2Provider, bool)
	}{
		{"google", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.Google
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return service.OAuth2Provider{
				Config: oauth2.Config{
					ClientID:     cfg.ClientID,
					ClientSecret: cfg.ClientSecret,
					RedirectURL:  cfg.RedirectURL,
					Scopes:       strings.Split(cfg.Scopes, ","),
					Endpoint:     google.Endpoint,
				},
				UserInfoFn: providers.JSONUserInfo("https://www.googleapis.com/oauth2/v3/userinfo", "sub", "email"),
			}, true
		}},
		{"github", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.Github
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return service.OAuth2Provider{
				Config: oauth2.Config{
					ClientID:     cfg.ClientID,
					ClientSecret: cfg.ClientSecret,
					RedirectURL:  cfg.RedirectURL,
					Scopes:       strings.Split(cfg.Scopes, ","),
					Endpoint:     github.Endpoint,
				},
				UserInfoFn: providers.JSONUserInfo("https://api.github.com/user", "id", "email"),
			}, true
		}},
		{"facebook", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.Facebook
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return service.OAuth2Provider{
				Config: oauth2.Config{
					ClientID:     cfg.ClientID,
					ClientSecret: cfg.ClientSecret,
					RedirectURL:  cfg.RedirectURL,
					Scopes:       strings.Split(cfg.Scopes, ","),
					Endpoint:     facebook.Endpoint,
				},
				UserInfoFn: providers.JSONUserInfo("https://graph.facebook.com/me?fields=id,email", "id", "email"),
			}, true
		}},
		{"discord", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.Discord
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return providers.Discord(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL), true
		}},
		{"gitlab", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.GitLab
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return providers.GitLab(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL), true
		}},
		{"slack", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.Slack
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return providers.Slack(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL), true
		}},
		{"linkedin", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.LinkedIn
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return providers.LinkedIn(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL), true
		}},
		{"spotify", func() (service.OAuth2Provider, bool) {
			cfg := e.Config.OAuth2.Spotify
			if cfg.ClientID == "" {
				return service.OAuth2Provider{}, false
			}
			return providers.Spotify(cfg.ClientID, cfg.ClientSecret, cfg.RedirectURL), true
		}},
	}

	for _, b := range builtins {
		if p, ok := b.config(); ok {
			e.RegisterOAuth2Provider(b.name, p)
		}
	}
	return nil
}

func (e *EzAuth) registerCustomProviders(ctx context.Context) error {
	customProvs, err := config.LoadCustomOAuth2Providers()
	if err != nil {
		return err
	}

	oidcCtx, cancel := context.WithTimeout(ctx, e.Config.TimeOut)
	defer cancel()

	for _, cp := range customProvs {
		var p service.OAuth2Provider
		if cp.IssuerURL != "" {
			p, err = providers.OIDC(oidcCtx, cp.IssuerURL, cp.ClientID, cp.ClientSecret, cp.RedirectURL, cp.Scopes)
			if err != nil {
				slog.Warn("skipping custom OIDC provider: discovery failed", "name", cp.Name, "err", err)
				continue
			}
		} else {
			p = service.OAuth2Provider{
				Config: oauth2.Config{
					ClientID:     cp.ClientID,
					ClientSecret: cp.ClientSecret,
					RedirectURL:  cp.RedirectURL,
					Scopes:       cp.Scopes,
					Endpoint: oauth2.Endpoint{
						AuthURL:  cp.AuthURL,
						TokenURL: cp.TokenURL,
					},
				},
				UserInfoFn: providers.JSONUserInfo(cp.UserinfoURL, cp.IDField, cp.EmailField),
			}
		}
		e.RegisterOAuth2Provider(cp.Name, p)
	}
	return nil
}

// Hook returns the currently registered Hook implementation.
func (e *EzAuth) Hook() service.Hook {
	return e.Service.Hook
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

// Impersonate mints a new token pair for targetUserID, acting on behalf of adminUser.
// ezauth performs no authorization check here: the caller is responsible for verifying
// that adminUser is allowed to impersonate (e.g. via adminUser.HasRole("admin")) before
// calling this method.
func (e *EzAuth) Impersonate(ctx context.Context, adminUser *models.User, targetUserID string) (*service.TokenResponse, error) {
	return e.Service.Impersonate(ctx, adminUser, targetUserID)
}

// StopImpersonating revokes an impersonation refresh token, ending that session.
func (e *EzAuth) StopImpersonating(ctx context.Context, impersonationRefreshToken string) error {
	return e.Service.StopImpersonating(ctx, impersonationRefreshToken)
}

// IsImpersonating reports whether the current cookie-based session is an impersonation
// session, and if so, the acting admin's user ID.
func (e *EzAuth) IsImpersonating(ctx context.Context) (string, bool) {
	return e.Handler.IsImpersonating(ctx)
}

// GetImpersonator returns the acting admin's user for the current cookie-based
// impersonation session.
func (e *EzAuth) GetImpersonator(ctx context.Context) (*models.User, error) {
	return e.Handler.GetImpersonator(ctx)
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

// GetImpersonatorID returns the acting admin's user ID from a JWT-authenticated
// (Bearer token) request context, as set by AuthMiddleware from the token's "act"
// claim. This is the Bearer/JWT-mode counterpart to EzAuth.IsImpersonating and
// EzAuth.GetImpersonator, which operate on cookie-based sessions instead — the two
// are backed by different mechanisms and aren't interchangeable.
func GetImpersonatorID(ctx context.Context) (string, error) {
	return handler.GetImpersonatorID(ctx)
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
