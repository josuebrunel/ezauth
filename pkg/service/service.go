// Package service provides the business logic for ezauth.
package service

import (
	"fmt"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/repository"
	"github.com/josuebrunel/gopkg/xlog"
)

// Auth handles the core authentication logic.
type Auth struct {
	Cfg        *config.Config
	Repo       *repository.Repository
	Mailer     Mailer
	SMS        SMSSender
	PathPrefix string
	// Hook is read without synchronization at every request-handling call
	// site; set it directly or via SetHook only during setup, before Auth
	// starts serving requests.
	Hook              Hook
	WebAuthn          *webauthn.WebAuthn
	jwtKeys           *jwtKeys
	customProvidersMu sync.RWMutex
	customProviders   map[string]OAuth2Provider
}

// New creates a new Auth service with the given config and repository.
func New(cfg *config.Config, repo *repository.Repository, pathPrefix string) (*Auth, error) {
	jwtKeys, err := newJWTKeys(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signing configuration: %w", err)
	}

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

	if cfg.AccountLockout == (config.AccountLockout{}) {
		// A fully zero-value AccountLockout means either it was never set
		// (config.Config{} built by hand, bypassing LoadConfig's
		// default:"true" env tag -- common in tests and for callers who
		// load their own config another way) or Enabled was deliberately
		// left false alongside untouched MaxAttempts/LockoutDuration --
		// these two cases are indistinguishable from a bool alone, so warn
		// either way. config.LoadConfig() itself fails fast on this instead,
		// since it's the one path where the zero value can only mean a
		// misconfigured production deployment, never a deliberately minimal
		// hand-built Config.
		xlog.Warn("AccountLockout is unset (brute-force lockout disabled): call config.LoadConfig() to get its default:\"true\" enablement, or set Cfg.AccountLockout explicitly if this is intentional")
	}

	a := &Auth{
		Cfg:             cfg,
		Repo:            repo,
		Mailer:          mailer,
		SMS:             sms,
		PathPrefix:      pathPrefix,
		jwtKeys:         jwtKeys,
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

	return a, nil
}

// SetHook registers hook as the consumer-supplied Hook implementation.
// It's still wrapped with audit-log persistence (see auditHook in hook.go),
// so replacing the hook never disables built-in audit logging.
//
// SetHook must only be called during setup, before Auth starts serving
// requests (e.g. before calling Handler.Run/ServeHTTP) -- it reassigns Hook
// with no synchronization, and every request-handling call site reads Hook
// without a lock for the same reason SetHook itself isn't one: Hook is
// intended to be configured once, not swapped at runtime under live traffic.
func (a *Auth) SetHook(hook Hook) {
	a.Hook = newAuditHook(a, hook)
}

// NewFromConfig creates a new Auth service from a config.
// It handles the repository initialization.
func NewFromConfig(cfg *config.Config, pathPrefix string) (*Auth, error) {
	repo, err := repository.Open(repository.Opts{
		Dialect:         cfg.DB.Dialect,
		DSN:             cfg.DB.DSN,
		Schema:          cfg.DB.Schema,
		MaxOpenConns:    cfg.DB.MaxOpenConns,
		MaxIdleConns:    cfg.DB.MaxIdleConns,
		ConnMaxLifetime: cfg.DB.ConnMaxLifetime,
	})
	if err != nil {
		return nil, err
	}
	return New(cfg, repo, pathPrefix)
}
