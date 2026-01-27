// Package config provides configuration management for ezauth.
package config

import (
	"time"

	"github.com/josuebrunel/gopkg/xenv"
	"github.com/josuebrunel/gopkg/xlog"
)

// Database defines the database connection settings.
type Database struct {
	Dialect string `json:"dialect" env:"DB_DIALECT" default:"sqlite3"`
	DSN     string `json:"dsn" env:"DB_DSN" default:"ezauth.db"`
}

// OAuth2Google defines the settings for Google OAuth2.
type OAuth2Google struct {
	Name         string `json:"name" env:"OAUTH2_GOOGLE_NAME" default:"google"`
	ClientID     string `json:"client_id" env:"OAUTH2_GOOGLE_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_GOOGLE_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_GOOGLE_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_GOOGLE_SCOPES"`
}

// OAuth2Github defines the settings for GitHub OAuth2.
type OAuth2Github struct {
	Name         string `json:"name" env:"OAUTH2_GITHUB_NAME" default:"github"`
	ClientID     string `json:"client_id" env:"OAUTH2_GITHUB_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_GITHUB_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_GITHUB_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_GITHUB_SCOPES"`
}

// OAuth2Facebook defines the settings for Facebook OAuth2.
type OAuth2Facebook struct {
	Name         string `json:"name" env:"OAUTH2_FACEBOOK_NAME" default:"facebook"`
	ClientID     string `json:"client_id" env:"OAUTH2_FACEBOOK_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_FACEBOOK_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_FACEBOOK_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_FACEBOOK_SCOPES"`
}

// OAuth2 defines the general OAuth2 settings and provider-specific configurations.
type OAuth2 struct {
	CallbackURL string `json:"callback_url" env:"OAUTH2_CALLBACK_URL"`
	Google      OAuth2Google
	Github      OAuth2Github
	Facebook    OAuth2Facebook
}

// SMTP defines the settings for the SMTP mailer.
type SMTP struct {
	Host     string `json:"host" env:"SMTP_HOST"`
	Port     int    `json:"port" env:"SMTP_PORT" default:"587"`
	User     string `json:"user" env:"SMTP_USER"`
	Password string `json:"password" env:"SMTP_PASSWORD"`
	From     string `json:"from" env:"SMTP_FROM"`
}

// Config defines the overall configuration for ezauth.
type Config struct {
	Addr      string        `json:"addr" env:"ADDR" default:":8080"`
	BaseURL   string        `json:"base_url" env:"BASE_URL" default:"http://localhost:8080"`
	Debug     bool          `json:"debug" env:"DEBUG" default:"false"`
	DB        Database      `json:"db"`
	Secret    string        `json:"secret" env:"SECRET"`
	JWTSecret string        `json:"jwt_secret" env:"JWT_SECRET"`
	OAuth2    OAuth2        `json:"oauth2"`
	SMTP      SMTP          `json:"smtp"`
	TimeOut   time.Duration `json:"timeout" env:"TIMEOUT" default:"30s"`
}

// LoadConfig loads the configuration from environment variables.
// It uses the "EZAUTH_" prefix for environment variables.
func LoadConfig() (Config, error) {
	var cfg Config

	if err := xenv.LoadWithOptions(&cfg, xenv.Options{Prefix: "EZAUTH_"}); err != nil {
		xlog.Error("failed to load config", "err", err)
		return cfg, err
	}

	return cfg, nil
}
