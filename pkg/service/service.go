package service

import (
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
)

type Auth struct {
	Cfg  *config.Config
	Repo *repository.Repository
}

func New(cfg *config.Config) *Auth {
	repo := repository.New(repository.Opts{
		Dialect: cfg.DB.Dialect,
		DSN:     cfg.DB.DSN,
	})
	return &Auth{
		Cfg:  cfg,
		Repo: repo,
	}
}
