// Package service provides the business logic for ezauth.
package service

import (
	"sync"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
	"github.com/josuebrunel/gopkg/xlog"
)

// Auth handles the core authentication logic.
type Auth struct {
	Cfg               *config.Config
	Repo              *repository.Repository
	Mailer            Mailer
	PathPrefix        string
	Hook              Hook
	customProvidersMu sync.RWMutex
	customProviders   map[string]OAuth2Provider
}

// New creates a new Auth service with the given config and repository.
func New(cfg *config.Config, repo *repository.Repository, pathPrefix string) *Auth {
	var mailer Mailer
	if cfg.SMTP.Host != "" {
		mailer = NewSMTPMailer(cfg.SMTP)
	} else {
		mailer = NewMockMailer()
		xlog.Warn("SMTP not configured, using mock mailer — emails will not be sent")
	}

	return &Auth{
		Cfg:             cfg,
		Repo:            repo,
		Mailer:          mailer,
		PathPrefix:      pathPrefix,
		Hook:            DefaultHook{},
		customProviders: make(map[string]OAuth2Provider),
	}
}

// NewFromConfig creates a new Auth service from a config.
// It handles the repository initialization.
func NewFromConfig(cfg *config.Config, pathPrefix string) (*Auth, error) {
	repo, err := repository.Open(repository.Opts{
		Dialect: cfg.DB.Dialect,
		DSN:     cfg.DB.DSN,
		Schema:  cfg.DB.Schema,
	})
	if err != nil {
		return nil, err
	}
	return New(cfg, repo, pathPrefix), nil
}
