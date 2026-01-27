package service

import (
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
)

type Auth struct {
	Cfg    *config.Config
	Repo   *repository.Repository
	Mailer Mailer
}

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
