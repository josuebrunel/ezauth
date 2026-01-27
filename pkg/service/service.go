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

func New(cfg *config.Config) *Auth {
	repo := repository.New(repository.Opts{
		Dialect: cfg.DB.Dialect,
		DSN:     cfg.DB.DSN,
	})

	var mailer Mailer
	if cfg.SMTP.Host != "" {
		mailer = NewSMTPMailer(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.From)
	} else {
		mailer = &MockMailer{}
	}

	return &Auth{
		Cfg:    cfg,
		Repo:   repo,
		Mailer: mailer,
	}
}
