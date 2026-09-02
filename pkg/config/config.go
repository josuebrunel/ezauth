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

// SMS defines the settings for the SMS OTP provider (Twilio-compatible REST API).
// SMS OTP support is disabled unless AccountSID, AuthToken, and From are all set.
type SMS struct {
	AccountSID string `json:"account_sid" env:"SMS_TWILIO_ACCOUNT_SID"`
	AuthToken  string `json:"auth_token" env:"SMS_TWILIO_AUTH_TOKEN"`
	From       string `json:"from" env:"SMS_TWILIO_FROM"`
}

// SMSTemplates defines the customizable SMS OTP message template.
// Uses Go text/template syntax with {{.Variable}} placeholders.
// Available variable: {{.Code}}
type SMSTemplates struct {
	OTPBody string `json:"otp_body" env:"SMS_OTP_BODY" default:"Your verification code is: {{.Code}}"`
}

// EmailTemplates defines customizable email templates.
// Templates use Go text/template syntax with {{.Variable}} placeholders.
// Available variables: {{.Link}}, {{.Token}}, {{.Email}}
type EmailTemplates struct {
	PasswordlessSubject  string `json:"passwordless_subject" env:"EMAIL_PASSWORDLESS_SUBJECT" default:"Magic Link Login"`
	PasswordlessBody     string `json:"passwordless_body" env:"EMAIL_PASSWORDLESS_BODY" default:"Click the following link to login: {{.Link}}"`
	PasswordResetSubject string `json:"password_reset_subject" env:"EMAIL_PASSWORD_RESET_SUBJECT" default:"Password Reset Request"`
	PasswordResetBody    string `json:"password_reset_body" env:"EMAIL_PASSWORD_RESET_BODY" default:"Click the following link to reset your password: {{.Link}}"`
	InvitationSubject    string `json:"invitation_subject" env:"EMAIL_INVITATION_SUBJECT" default:"You've been invited"`
	InvitationBody       string `json:"invitation_body" env:"EMAIL_INVITATION_BODY" default:"Click the following link to accept your invitation: {{.Link}}"`

	// EmailChangeSubject/Body are sent to the *new* address to verify it before the change takes effect.
	EmailChangeSubject string `json:"email_change_subject" env:"EMAIL_CHANGE_SUBJECT" default:"Confirm your new email address"`
	EmailChangeBody    string `json:"email_change_body" env:"EMAIL_CHANGE_BODY" default:"Click the following link to confirm your new email address: {{.Link}}"`

	// EmailChangeNotify* are sent to the *current* address to warn that a change was requested (account-takeover mitigation).
	EmailChangeNotifySubject string `json:"email_change_notify_subject" env:"EMAIL_CHANGE_NOTIFY_SUBJECT" default:"Your email address is being changed"`
	EmailChangeNotifyBody    string `json:"email_change_notify_body" env:"EMAIL_CHANGE_NOTIFY_BODY" default:"A request was made to change the email on your account to {{.NewEmail}}. If this wasn't you, please secure your account immediately."`
}

// Invitation defines the invite-by-email onboarding settings.
type Invitation struct {
	TTL time.Duration `json:"ttl" env:"INVITATION_TTL" default:"168h"`
}

// Redirects defines the redirection URLs after successful actions.
type Redirects struct {
	AfterLogin    string `json:"after_login" env:"REDIRECT_AFTER_LOGIN" default:"/"`
	AfterRegister string `json:"after_register" env:"REDIRECT_AFTER_REGISTER" default:"/"`
}

// Pages defines the URLs for the authentication pages.
type Pages struct {
	Login            string `json:"login" env:"LOGIN_PAGE_URL" default:"/login"`
	Register         string `json:"register" env:"REGISTER_PAGE_URL" default:"/register"`
	MFAVerify        string `json:"mfa_verify" env:"MFA_VERIFY_PAGE_URL" default:"/mfa/verify"`
	InvitationAccept string `json:"invitation_accept" env:"INVITATION_ACCEPT_PAGE_URL" default:"/invitation/accept"`
}

// Hashing defines the password hashing algorithm and its parameters.
type Hashing struct {
	Algorithm string `json:"algorithm" env:"HASHING_ALGORITHM" default:"bcrypt"`
	// BcryptCost is the bcrypt work factor (4-31). Lower is faster but weaker; 14 is a
	// strong modern default for production. Tests should use a low value (e.g. 4, the
	// minimum) since correctness doesn't depend on bcrypt actually being slow.
	BcryptCost        int    `json:"bcrypt_cost" env:"HASHING_BCRYPT_COST" default:"14"`
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

// TrustedDevice defines the "remember this device" settings for skipping MFA
// step-up on subsequent logins from a device the user has already verified.
type TrustedDevice struct {
	TTL        time.Duration `json:"ttl" env:"TRUSTED_DEVICE_TTL" default:"720h"`
	CookieName string        `json:"cookie_name" env:"TRUSTED_DEVICE_COOKIE_NAME" default:"ezauth_device"`
}

// AccountLockout defines the brute-force lockout settings enforced by
// UserAuthenticate: after MaxAttempts consecutive failed logins, the account is
// locked (IsActive is cleared) for LockoutDuration.
type AccountLockout struct {
	Enabled         bool          `json:"enabled" env:"ACCOUNT_LOCKOUT_ENABLED" default:"true"`
	MaxAttempts     int           `json:"max_attempts" env:"ACCOUNT_LOCKOUT_MAX_ATTEMPTS" default:"5"`
	LockoutDuration time.Duration `json:"lockout_duration" env:"ACCOUNT_LOCKOUT_DURATION" default:"15m"`
}

// JWT defines asymmetric access-token signing settings. By default ezauth
// signs access tokens with symmetric HS256 (Config.JWTSecret) — set
// Algorithm to "RS256" or "EdDSA" (PrivateKey/PublicKey required, PEM
// encoded) to sign asymmetrically instead, so independent resource servers
// can verify ezauth-issued tokens via the JWKS endpoint
// (/.well-known/jwks.json) without holding a shared secret.
//
// PreviousPublicKey/PreviousKeyID let a key be rotated without invalidating
// already-issued tokens: set them to the outgoing key's public key/kid
// (KeyID, before rotating) so tokens it already signed keep verifying until
// they expire, while new tokens sign with the new PrivateKey/PublicKey/KeyID.
// KeyID/PreviousKeyID are optional; left unset, ezauth derives a stable kid
// from the corresponding public key.
type JWT struct {
	Algorithm         string `json:"algorithm" env:"JWT_ALGORITHM" default:"HS256"`
	PrivateKey        string `json:"-" env:"JWT_PRIVATE_KEY"`
	PublicKey         string `json:"public_key" env:"JWT_PUBLIC_KEY"`
	KeyID             string `json:"key_id" env:"JWT_KEY_ID"`
	PreviousPublicKey string `json:"previous_public_key" env:"JWT_PREVIOUS_PUBLIC_KEY"`
	PreviousKeyID     string `json:"previous_key_id" env:"JWT_PREVIOUS_KEY_ID"`
}

// AuditLog defines the persisted audit-log settings. When Enabled, ezauth
// records a row to the audit log for each security-relevant lifecycle event
// (login success/failure, password reset, impersonation, account lockout,
// etc.) — see service.Hook.
type AuditLog struct {
	Enabled bool `json:"enabled" env:"AUDIT_LOG_ENABLED" default:"true"`
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
	TrustedDevice  TrustedDevice  `json:"trusted_device"`
	AccountLockout AccountLockout `json:"account_lockout"`
	Invitation     Invitation     `json:"invitation"`
	OAuth2         OAuth2         `json:"oauth2"`
	SMTP           SMTP           `json:"smtp"`
	EmailTemplates EmailTemplates `json:"email_templates"`
	SMS            SMS            `json:"sms"`
	SMSTemplates   SMSTemplates   `json:"sms_templates"`
	Redirects      Redirects      `json:"redirects"`
	Pages          Pages          `json:"pages"`
	TimeOut        time.Duration  `json:"timeout" env:"TIMEOUT" default:"30s"`
	MFAIssuer      string         `json:"mfa_issuer" env:"MFA_ISSUER" default:"EzAuth"`
	WebAuthn       WebAuthn       `json:"webauthn"`
	AuditLog       AuditLog       `json:"audit_log"`
	JWT            JWT            `json:"jwt"`
}

// LoadConfig loads the configuration from environment variables.
// It uses the "EZAUTH_" prefix for environment variables.
// Sanitized returns a copy of the config with all secret fields redacted.
func (c Config) Sanitized() Config {
	c.JWTSecret = "***"
	c.CSRFSecret = "***"
	c.ApiKey = "***"
	c.SMTP.Password = "***"
	c.SMS.AuthToken = "***"
	c.OAuth2.Google.ClientSecret = "***"
	c.OAuth2.Github.ClientSecret = "***"
	c.OAuth2.Facebook.ClientSecret = "***"
	c.OAuth2.Discord.ClientSecret = "***"
	c.OAuth2.GitLab.ClientSecret = "***"
	c.OAuth2.Slack.ClientSecret = "***"
	c.OAuth2.LinkedIn.ClientSecret = "***"
	c.OAuth2.Spotify.ClientSecret = "***"
	c.JWT.PrivateKey = "***"
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
