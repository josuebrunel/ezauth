// Package service provides the business logic for ezauth.
package service

import (
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
)

// Auth handles the core authentication logic.
type Auth struct {
	Cfg    *config.Config
	Repo   *repository.Repository
	Mailer Mailer
}

// New creates a new Auth service with the given config and repository.
func New(cfg *config.Config, repo *repository.Repository) *Auth {
	var mailer Mailer
	if cfg.SMTP.Host != "" {
		mailer = NewSMTPMailer(cfg.SMTP)
	} else {
		mailer = NewMockMailer()
	}

	return &Auth{
		Cfg:    cfg,
		Repo:   repo,
		Mailer: mailer,
	}
}

// NewFromConfig creates a new Auth service from a config.
// It handles the repository initialization.
func NewFromConfig(cfg *config.Config) (*Auth, error) {
	repo, err := repository.Open(repository.Opts{
		Dialect: cfg.DB.Dialect,
		DSN:     cfg.DB.DSN,
	})
	if err != nil {
		return nil, err
	}
	return New(cfg, repo), nil
}
