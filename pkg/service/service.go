package service

import (
	"errors"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrInvalidToken = errors.New("invalid token")
)

type Auth struct {
	Config *Config
}

// New creates a new instance of EzAuth
func New(config *Config) *Auth {
	if config == nil {
		config = &Config{}
	}
	return &Auth{
		Config: config,
	}
}
