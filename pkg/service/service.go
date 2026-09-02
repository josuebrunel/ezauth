// Package service provides the business logic for ezauth.
package service

import (
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
	"github.com/josuebrunel/gopkg/xlog"
)

// Auth handles the core authentication logic.
type Auth struct {
	Cfg               *config.Config
	Repo              *repository.Repository
	Mailer            Mailer
	SMS               SMSSender
	PathPrefix        string
	Hook              Hook
	WebAuthn          *webauthn.WebAuthn
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

	var sms SMSSender
	if cfg.SMS.AccountSID != "" && cfg.SMS.AuthToken != "" && cfg.SMS.From != "" {
		sms = NewTwilioSMSSender(cfg.SMS)
	} else {
		sms = NewMockSMSSender()
		xlog.Warn("SMS provider not configured, using mock sender — SMS OTP codes will not be sent")
	}

	a := &Auth{
		Cfg:             cfg,
		Repo:            repo,
		Mailer:          mailer,
		SMS:             sms,
		PathPrefix:      pathPrefix,
		customProviders: make(map[string]OAuth2Provider),
	}
	a.Hook = newAuditHook(a, DefaultHook{})

	if cfg.WebAuthn.RPID != "" && cfg.WebAuthn.RPOrigins != "" {
		wa, err := webauthn.New(&webauthn.Config{
			RPID:          cfg.WebAuthn.RPID,
			RPDisplayName: cfg.WebAuthn.RPDisplayName,
			RPOrigins:     strings.Split(cfg.WebAuthn.RPOrigins, ","),
		})
		if err != nil {
			xlog.Error("failed to configure webauthn, passkey support disabled", "err", err)
		} else {
			a.WebAuthn = wa
		}
	} else {
		xlog.Warn("WEBAUTHN_RP_ID/WEBAUTHN_RP_ORIGINS not set, passkey support disabled")
	}

	return a
}

// SetHook registers hook as the consumer-supplied Hook implementation.
// It's still wrapped with audit-log persistence (see auditHook in hook.go),
// so replacing the hook never disables built-in audit logging.
func (a *Auth) SetHook(hook Hook) {
	a.Hook = newAuditHook(a, hook)
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
