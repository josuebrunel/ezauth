package config

import (
	"time"

	"github.com/josuebrunel/gopkg/xenv"
	"github.com/josuebrunel/gopkg/xlog"
)

type Database struct {
	Dialect string `json:"dialect" env:"DB_DIALECT" default:"sqlite3"`
	DSN     string `json:"dsn" env:"DB_DSN" default:"ezauth.db"`
}

type OAuth2Google struct {
	Name         string `json:"name" env:"OAUTH2_GOOGLE_NAME" default:"google"`
	ClientID     string `json:"client_id" env:"OAUTH2_GOOGLE_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_GOOGLE_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_GOOGLE_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_GOOGLE_SCOPES"`
}

type OAuth2Github struct {
	Name         string `json:"name" env:"OAUTH2_GITHUB_NAME" default:"github"`
	ClientID     string `json:"client_id" env:"OAUTH2_GITHUB_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_GITHUB_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_GITHUB_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_GITHUB_SCOPES"`
}

type OAuth2Facebook struct {
	Name         string `json:"name" env:"OAUTH2_FACEBOOK_NAME" default:"facebook"`
	ClientID     string `json:"client_id" env:"OAUTH2_FACEBOOK_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_FACEBOOK_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_FACEBOOK_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_FACEBOOK_SCOPES"`
}

type OAuth2 struct {
	Google   OAuth2Google
	Github   OAuth2Github
	Facebook OAuth2Facebook
}

type SMTP struct {
	Host     string `json:"host" env:"SMTP_HOST"`
	Port     int    `json:"port" env:"SMTP_PORT" default:"587"`
	Username string `json:"username" env:"SMTP_USERNAME"`
	Password string `json:"password" env:"SMTP_PASSWORD"`
	From     string `json:"from" env:"SMTP_FROM"`
}

type Config struct {
	Addr      string        `json:"addr" env:"ADDR" default:":8080"`
	Debug     bool          `json:"debug" env:"DEBUG" default:"false"`
	DB        Database      `json:"db"`
	Secret    string        `json:"secret" env:"SECRET"`
	JWTSecret string        `json:"jwt_secret" env:"JWT_SECRET"`
	OAuth2    OAuth2        `json:"oauth2"`
	SMTP      SMTP          `json:"smtp"`
	TimeOut   time.Duration `json:"timeout" env:"TIMEOUT" default:"30s"`
}

var V Config

func init() {
	var cfg Config

	if err := xenv.LoadWithOptions(&cfg, xenv.Options{Prefix: "EZAUTH_"}); err != nil {
		xlog.Error("failed to load config", "err", err)
		panic(err)
	}

	V = cfg
}
