// Package config provides configuration management for ezauth.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/josuebrunel/gopkg/xenv"
	"github.com/josuebrunel/gopkg/xlog"
)

// Database defines the database connection settings.
type Database struct {
	Dialect string `json:"dialect" env:"DB_DIALECT" default:"sqlite3"`
	DSN     string `json:"dsn" env:"DB_DSN" default:"ezauth.db"`
	Schema  string `json:"schema" env:"DB_SCHEMA"`
}

// OAuth2Google defines the settings for Google OAuth2.
type OAuth2Google struct {
	Name         string `json:"name" env:"OAUTH2_GOOGLE_NAME" default:"google"`
	ClientID     string `json:"client_id" env:"OAUTH2_GOOGLE_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_GOOGLE_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_GOOGLE_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_GOOGLE_SCOPES" default:"openid,profile,email"`
}

// OAuth2Github defines the settings for GitHub OAuth2.
type OAuth2Github struct {
	Name         string `json:"name" env:"OAUTH2_GITHUB_NAME" default:"github"`
	ClientID     string `json:"client_id" env:"OAUTH2_GITHUB_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_GITHUB_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_GITHUB_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_GITHUB_SCOPES" default:"user:email"`
}

// OAuth2Facebook defines the settings for Facebook OAuth2.
type OAuth2Facebook struct {
	Name         string `json:"name" env:"OAUTH2_FACEBOOK_NAME" default:"facebook"`
	ClientID     string `json:"client_id" env:"OAUTH2_FACEBOOK_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_FACEBOOK_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_FACEBOOK_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_FACEBOOK_SCOPES" default:"email,public_profile"`
}

// OAuth2Discord defines the settings for Discord OAuth2.
type OAuth2Discord struct {
	Name         string `json:"name" env:"OAUTH2_DISCORD_NAME" default:"discord"`
	ClientID     string `json:"client_id" env:"OAUTH2_DISCORD_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_DISCORD_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_DISCORD_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_DISCORD_SCOPES" default:"identify,email"`
}

// OAuth2GitLab defines the settings for GitLab OAuth2.
type OAuth2GitLab struct {
	Name         string `json:"name" env:"OAUTH2_GITLAB_NAME" default:"gitlab"`
	ClientID     string `json:"client_id" env:"OAUTH2_GITLAB_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_GITLAB_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_GITLAB_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_GITLAB_SCOPES" default:"read_user"`
}

// OAuth2Slack defines the settings for Slack OAuth2.
type OAuth2Slack struct {
	Name         string `json:"name" env:"OAUTH2_SLACK_NAME" default:"slack"`
	ClientID     string `json:"client_id" env:"OAUTH2_SLACK_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_SLACK_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_SLACK_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_SLACK_SCOPES" default:"openid,email"`
}

// OAuth2LinkedIn defines the settings for LinkedIn OAuth2.
type OAuth2LinkedIn struct {
	Name         string `json:"name" env:"OAUTH2_LINKEDIN_NAME" default:"linkedin"`
	ClientID     string `json:"client_id" env:"OAUTH2_LINKEDIN_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_LINKEDIN_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_LINKEDIN_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_LINKEDIN_SCOPES" default:"openid,profile,email"`
}

// OAuth2Spotify defines the settings for Spotify OAuth2.
type OAuth2Spotify struct {
	Name         string `json:"name" env:"OAUTH2_SPOTIFY_NAME" default:"spotify"`
	ClientID     string `json:"client_id" env:"OAUTH2_SPOTIFY_CLIENT_ID"`
	ClientSecret string `json:"client_secret" env:"OAUTH2_SPOTIFY_CLIENT_SECRET"`
	RedirectURL  string `json:"redirect_url" env:"OAUTH2_SPOTIFY_REDIRECT_URL"`
	Scopes       string `json:"scopes" env:"OAUTH2_SPOTIFY_SCOPES" default:"user-read-email,user-read-private"`
}

// OAuth2 defines the general OAuth2 settings and provider-specific configurations.
type OAuth2 struct {
	CallbackURL string `json:"callback_url" env:"OAUTH2_CALLBACK_URL"`
	Google      OAuth2Google
	Github      OAuth2Github
	Facebook    OAuth2Facebook
	Discord     OAuth2Discord
	GitLab      OAuth2GitLab
	Slack       OAuth2Slack
	LinkedIn    OAuth2LinkedIn
	Spotify     OAuth2Spotify
}

// SMTP defines the settings for the SMTP mailer.
type SMTP struct {
	Host     string `json:"host" env:"SMTP_HOST"`
	Port     int    `json:"port" env:"SMTP_PORT" default:"587"`
	User     string `json:"user" env:"SMTP_USER"`
	Password string `json:"password" env:"SMTP_PASSWORD"`
	From     string `json:"from" env:"SMTP_FROM"`
}

// EmailTemplates defines customizable email templates.
// Templates use Go text/template syntax with {{.Variable}} placeholders.
// Available variables: {{.Link}}, {{.Token}}, {{.Email}}
type EmailTemplates struct {
	PasswordlessSubject  string `json:"passwordless_subject" env:"EMAIL_PASSWORDLESS_SUBJECT" default:"Magic Link Login"`
	PasswordlessBody     string `json:"passwordless_body" env:"EMAIL_PASSWORDLESS_BODY" default:"Click the following link to login: {{.Link}}"`
	PasswordResetSubject string `json:"password_reset_subject" env:"EMAIL_PASSWORD_RESET_SUBJECT" default:"Password Reset Request"`
	PasswordResetBody    string `json:"password_reset_body" env:"EMAIL_PASSWORD_RESET_BODY" default:"Click the following link to reset your password: {{.Link}}"`
}

// Redirects defines the redirection URLs after successful actions.
type Redirects struct {
	AfterLogin    string `json:"after_login" env:"REDIRECT_AFTER_LOGIN" default:"/"`
	AfterRegister string `json:"after_register" env:"REDIRECT_AFTER_REGISTER" default:"/"`
}

// Pages defines the URLs for the authentication pages.
type Pages struct {
	Login     string `json:"login" env:"LOGIN_PAGE_URL" default:"/login"`
	Register  string `json:"register" env:"REGISTER_PAGE_URL" default:"/register"`
	MFAVerify string `json:"mfa_verify" env:"MFA_VERIFY_PAGE_URL" default:"/mfa/verify"`
}

// Hashing defines the password hashing algorithm and its parameters.
type Hashing struct {
	Algorithm         string `json:"algorithm" env:"HASHING_ALGORITHM" default:"bcrypt"`
	Argon2Memory      uint32 `json:"argon2_memory" env:"HASHING_ARGON2_MEMORY" default:"65536"`
	Argon2Iterations  uint32 `json:"argon2_iterations" env:"HASHING_ARGON2_ITERATIONS" default:"3"`
	Argon2Parallelism uint8  `json:"argon2_parallelism" env:"HASHING_ARGON2_PARALLELISM" default:"4"`
	Argon2SaltLength  uint32 `json:"argon2_salt_length" env:"HASHING_ARGON2_SALT_LENGTH" default:"16"`
	Argon2KeyLength   uint32 `json:"argon2_key_length" env:"HASHING_ARGON2_KEY_LENGTH" default:"32"`
}

// WebAuthn defines the Relying Party settings for WebAuthn/passkey support.
// RPID should be the effective domain (e.g. "example.com", no scheme/port).
// RPOrigins is a comma-separated list of allowed origins (e.g. "https://example.com").
// WebAuthn support is disabled unless both RPID and RPOrigins are set.
type WebAuthn struct {
	RPID          string `json:"rp_id" env:"WEBAUTHN_RP_ID"`
	RPDisplayName string `json:"rp_display_name" env:"WEBAUTHN_RP_DISPLAY_NAME" default:"EzAuth"`
	RPOrigins     string `json:"rp_origins" env:"WEBAUTHN_RP_ORIGINS"`
}

// RateLimit defines the rate limiting configuration.
type RateLimit struct {
	Enabled    bool          `json:"enabled" env:"RATE_LIMIT_ENABLED" default:"false"`
	Requests   int           `json:"requests" env:"RATE_LIMIT_REQUESTS" default:"10"`
	Window     time.Duration `json:"window" env:"RATE_LIMIT_WINDOW" default:"1m"`
	ByClientIP bool          `json:"by_client_ip" env:"RATE_LIMIT_BY_CLIENT_IP" default:"true"`
}

// Config defines the overall configuration for ezauth.
type Config struct {
	Addr           string         `json:"addr" env:"ADDR" default:":8080"`
	BaseURL        string         `json:"base_url" env:"BASE_URL" default:"http://localhost:8080"`
	ApiKey         string         `json:"api_key" env:"API_KEY" required:"true"`
	Debug          bool           `json:"debug" env:"DEBUG" default:"false"`
	DB             Database       `json:"db"`
	JWTSecret      string         `json:"jwt_secret" env:"JWT_SECRET" required:"true"`
	CSRFSecret     string         `json:"csrf_secret" env:"CSRF_SECRET"`
	Hashing        Hashing        `json:"hashing"`
	RateLimit      RateLimit      `json:"rate_limit"`
	OAuth2         OAuth2         `json:"oauth2"`
	SMTP           SMTP           `json:"smtp"`
	EmailTemplates EmailTemplates `json:"email_templates"`
	Redirects      Redirects      `json:"redirects"`
	Pages          Pages          `json:"pages"`
	TimeOut        time.Duration  `json:"timeout" env:"TIMEOUT" default:"30s"`
	MFAIssuer      string         `json:"mfa_issuer" env:"MFA_ISSUER" default:"EzAuth"`
	WebAuthn       WebAuthn       `json:"webauthn"`
}

// LoadConfig loads the configuration from environment variables.
// It uses the "EZAUTH_" prefix for environment variables.
// Sanitized returns a copy of the config with all secret fields redacted.
func (c Config) Sanitized() Config {
	c.JWTSecret = "***"
	c.CSRFSecret = "***"
	c.ApiKey = "***"
	c.SMTP.Password = "***"
	c.OAuth2.Google.ClientSecret = "***"
	c.OAuth2.Github.ClientSecret = "***"
	c.OAuth2.Facebook.ClientSecret = "***"
	c.OAuth2.Discord.ClientSecret = "***"
	c.OAuth2.GitLab.ClientSecret = "***"
	c.OAuth2.Slack.ClientSecret = "***"
	c.OAuth2.LinkedIn.ClientSecret = "***"
	c.OAuth2.Spotify.ClientSecret = "***"
	return c
}

func LoadConfig() (Config, error) {
	var cfg Config

	if err := xenv.LoadWithOptions(&cfg, xenv.Options{Prefix: "EZAUTH_"}); err != nil {
		xlog.Error("failed to load config", "err", err)
		return cfg, err
	}

	return cfg, nil
}

// CustomOAuth2Provider represents a dynamically configured custom OAuth2 provider.
type CustomOAuth2Provider struct {
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	IssuerURL    string
	AuthURL      string
	TokenURL     string
	UserinfoURL  string
	IDField      string
	EmailField   string
}

// LoadCustomOAuth2Providers reads dynamically declared custom OAuth2 providers from the environment.
// Reads EZAUTH_OAUTH2_PROVIDERS (comma-separated names) and prefix EZAUTH_OAUTH2_<NAME>_ values.
func LoadCustomOAuth2Providers() ([]CustomOAuth2Provider, error) {
	providersStr := os.Getenv("EZAUTH_OAUTH2_PROVIDERS")
	if providersStr == "" {
		return nil, nil
	}

	var customProviders []CustomOAuth2Provider
	names := strings.Split(providersStr, ",")
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		upperName := strings.ToUpper(name)
		prefix := fmt.Sprintf("EZAUTH_OAUTH2_%s_", upperName)

		clientID := os.Getenv(prefix + "CLIENT_ID")
		clientSecret := os.Getenv(prefix + "CLIENT_SECRET")
		redirectURL := os.Getenv(prefix + "REDIRECT_URL")
		scopesStr := os.Getenv(prefix + "SCOPES")

		if clientID == "" {
			return nil, fmt.Errorf("missing required environment variable: %sCLIENT_ID", prefix)
		}
		if clientSecret == "" {
			return nil, fmt.Errorf("missing required environment variable: %sCLIENT_SECRET", prefix)
		}
		if redirectURL == "" {
			return nil, fmt.Errorf("missing required environment variable: %sREDIRECT_URL", prefix)
		}

		var scopes []string
		if scopesStr != "" {
			parts := strings.Split(scopesStr, ",")
			for _, p := range parts {
				scopes = append(scopes, strings.TrimSpace(p))
			}
		}

		issuerURL := os.Getenv(prefix + "ISSUER_URL")
		authURL := os.Getenv(prefix + "AUTH_URL")
		tokenURL := os.Getenv(prefix + "TOKEN_URL")
		userinfoURL := os.Getenv(prefix + "USERINFO_URL")

		idField := os.Getenv(prefix + "ID_FIELD")
		if idField == "" {
			idField = "id"
		}
		emailField := os.Getenv(prefix + "EMAIL_FIELD")
		if emailField == "" {
			emailField = "email"
		}

		if issuerURL == "" {
			if authURL == "" {
				return nil, fmt.Errorf("missing required environment variable for manual config: %sAUTH_URL", prefix)
			}
			if tokenURL == "" {
				return nil, fmt.Errorf("missing required environment variable for manual config: %sTOKEN_URL", prefix)
			}
			if userinfoURL == "" {
				return nil, fmt.Errorf("missing required environment variable for manual config: %sUSERINFO_URL", prefix)
			}
		}

		customProviders = append(customProviders, CustomOAuth2Provider{
			Name:         name,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			IssuerURL:    issuerURL,
			AuthURL:      authURL,
			TokenURL:     tokenURL,
			UserinfoURL:  userinfoURL,
			IDField:      idField,
			EmailField:   emailField,
		})
	}

	return customProviders, nil
}
