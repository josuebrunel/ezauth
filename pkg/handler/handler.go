// Package handler provides the HTTP handlers for ezauth.
package handler

import (
	"context"
	"encoding/gob"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	csrf "filippo.io/csrf/gorilla"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/josuebrunel/ezauth/pkg/handler/docs"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
	httpSwagger "github.com/swaggo/http-swagger"
)

// HTTP server timeouts and shutdown grace period for Run(). Not exposed via
// config: these are conservative, generally-safe defaults for an auth
// service; callers who need different values can build their own
// *http.Server around Handler (it implements http.Handler) instead of
// calling Run().
const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownTimeout   = 15 * time.Second

	// defaultMaxBodyBytes caps request bodies handled by the default
	// middleware chain. ezauth's JSON payloads (credentials, WebAuthn
	// attestation objects, etc.) are all well under this; it exists to
	// bound memory use against oversized/malicious request bodies rather
	// than to accommodate any legitimate large payload.
	defaultMaxBodyBytes = 1 << 20 // 1 MiB
)

// LoadUserMiddleware is a middleware that loads the authenticated user into the context.
// This allows downstream handlers to use GetSessionUser(ctx) without the Handler instance.
func (h *Handler) LoadUserMiddleware(next http.Handler) http.Handler {
	return ezmiddleware.LoadUserMiddleware(h.GetSessionUser)(next)
}

// OrgLoaderMiddleware is a middleware that resolves the "current organization"
// for a request via loader (app-supplied — ezauth doesn't presume how an org
// is identified) and loads it into the context. Downstream handlers read it
// via GetSessionOrg(ctx).
func (h *Handler) OrgLoaderMiddleware(loader ezmiddleware.OrgLoader) func(http.Handler) http.Handler {
	return ezmiddleware.OrgLoaderMiddleware(loader)
}

// SessionMiddleware combines LoadAndSave and LoadUserMiddleware.
// It ensures session data is loaded/saved and the user is populated in the context.
// It also stashes the session tokens and cookie-mode impersonator ID into the
// context so handlers and templates can read them via the package-level
// helpers (handler.GetSessionTokens / CurrentImpersonatorID) without a Handler.
func (h *Handler) SessionMiddleware(next http.Handler) http.Handler {
	base := ezmiddleware.SessionMiddleware(h.Session, h.GetSessionUser)
	return base(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(h.stashSessionContext(r.Context())))
	}))
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Handler handles all authentication-related HTTP requests.
type Handler struct {
	path    string
	r       *chi.Mux
	svc     *service.Auth
	Session *scs.SessionManager
}

// HandlerOption defines a functional option for configuring the Handler.
type HandlerOption func(*Handler)

// WithRouter sets a custom chi router for the Handler.
func WithRouter(r *chi.Mux) HandlerOption {
	return func(h *Handler) {
		h.r = r
	}
}

func init() {
	// Register types for session
	gob.Register(map[string]string{})
}

// New creates a new Handler with the given service and path.
// path is the base URL path where the authentication routes will be mounted.
// @title EzAuth API
// @version 1.0
// @description Authentication service/library for Go.
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-API-Key
func New(svc *service.Auth, path string, options ...HandlerOption) *Handler {
	h := &Handler{
		path: path,
		r:    chi.NewRouter(),
		svc:  svc,
	}

	secureCookies := h.svc.Cfg.ForceSecureCookies || strings.HasPrefix(h.svc.Cfg.BaseURL, "https://")
	if !secureCookies && !h.svc.Cfg.Debug {
		xlog.Warn("session/CSRF cookies are not marked Secure: BASE_URL doesn't start with https:// and FORCE_SECURE_COOKIES is unset. If ezauth sits behind a TLS-terminating reverse proxy, set EZAUTH_FORCE_SECURE_COOKIES=true.")
	}

	// Initialize Session Manager
	h.Session = scs.New()
	h.Session.Cookie.Name = "ezauthsess"
	h.Session.Cookie.HttpOnly = true
	h.Session.Cookie.Secure = secureCookies
	h.Session.Cookie.Persist = true

	for _, opt := range options {
		opt(h)
	}

	// Default middlewares if router was newly created
	if len(options) == 0 {
		h.r.Use(middleware.Logger)
		h.r.Use(middleware.RequestID)
		// chi's RealIP unconditionally trusts True-Client-IP/X-Real-IP/
		// X-Forwarded-For from any client, with no trusted-proxy allowlist.
		// Only register it when the operator has confirmed ezauth sits
		// behind a reverse proxy that sets/overwrites these headers itself
		// -- otherwise leave r.RemoteAddr as the raw (unspoofable) TCP peer
		// address the rate limiter keys on.
		if h.svc.Cfg.TrustProxyHeaders {
			h.r.Use(middleware.RealIP)
		}
		h.r.Use(ezmiddleware.MaxBodyBytes(defaultMaxBodyBytes))
		h.r.Use(ezmiddleware.NewRateLimiter(ezmiddleware.RateLimitConfig{
			Enabled:    h.svc.Cfg.RateLimit.Enabled,
			Requests:   h.svc.Cfg.RateLimit.Requests,
			Window:     h.svc.Cfg.RateLimit.Window,
			ByClientIP: h.svc.Cfg.RateLimit.ByClientIP,
		}).Middleware)
		h.r.Use(middleware.Recoverer)
		h.r.Use(h.Session.LoadAndSave)
	}

	h.r.Get("/ping", h.Ping)
	h.r.Get("/swagger/*", httpSwagger.WrapHandler)
	h.r.Get("/.well-known/jwks.json", h.JWKS)

	// Initialize routes
	routePath := "/" + h.path
	if h.path == "" {
		routePath = "/"
	}
	h.r.Route(routePath, func(r chi.Router) {
		// Routes that CANNOT have API Key (callbacks)
		r.Get("/oauth2/{provider}/callback", h.OAuth2Callback)

		// Form handlers (HTML Forms)
		r.Group(func(r chi.Router) {
			// CSRF Middleware
			csrfKey := h.svc.Cfg.CSRFSecret
			if csrfKey == "" {
				// Logged at Error, not Warn: this is a silent security
				// downgrade (CSRF and JWT signing share a key) that's easy
				// to miss at Warn level in production log pipelines.
				xlog.Error("CSRF_SECRET not set, falling back to JWT_SECRET -- this reuses the JWT signing key for CSRF protection, weakening key separation. Set a dedicated EZAUTH_CSRF_SECRET.")
				csrfKey = h.svc.Cfg.JWTSecret
			}
			r.Use(csrf.Protect([]byte(csrfKey), csrf.Secure(secureCookies)))

			r.Get("/csrf", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-CSRF-Token", csrf.Token(r))
				WriteJSONResponse(w, http.StatusOK, map[string]string{"csrf_token": csrf.Token(r)}, nil)
			})

			r.Get("/register", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, h.svc.Cfg.Pages.Register, http.StatusFound)
			})
			r.Post("/register", h.FormRegister)
			r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, h.svc.Cfg.Pages.Login, http.StatusFound)
			})
			r.Post("/login", h.FormLogin)
			r.Post("/logout", h.FormLogout)
			r.Post("/impersonate", h.FormImpersonate)
			r.Post("/impersonate/stop", h.FormStopImpersonation)
			r.Post("/password-reset/request", h.FormPasswordResetRequest)
			r.Post("/password-reset/confirm", h.FormPasswordResetConfirm)
			r.Post("/email-change/request", h.FormEmailChangeRequest)
			r.Get("/email-change/confirm", h.FormEmailChangeConfirm)
			r.Post("/passwordless/request", h.FormPasswordlessRequest)
			r.Get("/passwordless/login", h.FormPasswordlessLogin)
			r.Post("/sms-otp/request", h.FormSMSOTPRequest)
			r.Post("/sms-otp/verify", h.FormSMSOTPVerify)
			r.Get("/oauth2/{provider}/login", h.OAuth2Login)
			r.Get("/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, h.svc.Cfg.Pages.MFAVerify, http.StatusFound)
			})
			r.Post("/mfa/login/verify", h.FormMFALoginVerify)
			r.Post("/mfa/enroll", h.FormMFAEnroll)
			r.Post("/mfa/confirm", h.FormMFAConfirm)
			r.Post("/mfa/disable", h.FormMFADisable)
			r.Post("/webauthn/login/begin", h.FormWebauthnLoginBegin)
			r.Post("/webauthn/login/finish", h.FormWebauthnLoginFinish)
			r.Post("/webauthn/register/begin", h.FormWebauthnRegisterBegin)
			r.Post("/webauthn/register/finish", h.FormWebauthnRegisterFinish)
			r.Get("/webauthn/credentials", h.FormWebauthnCredentialsList)
			r.Delete("/webauthn/credentials/{id}", h.FormWebauthnCredentialDelete)
			r.Get("/trusted-devices", h.FormTrustedDevicesList)
			r.Delete("/trusted-devices/{id}", h.FormTrustedDeviceRevoke)
			r.Get("/sessions", h.FormSessionsList)
			r.Delete("/sessions/{id}", h.FormSessionRevoke)
			r.Delete("/sessions", h.FormSessionsRevokeAll)
			r.Post("/api-keys", h.FormAPIKeyCreate)
			r.Get("/api-keys", h.FormAPIKeysList)
			r.Delete("/api-keys/{id}", h.FormAPIKeyRevoke)
			r.Get("/invitation/accept", func(w http.ResponseWriter, r *http.Request) {
				target := h.svc.Cfg.Pages.InvitationAccept
				if token := r.URL.Query().Get("token"); token != "" {
					target += "?token=" + url.QueryEscape(token)
				}
				http.Redirect(w, r, target, http.StatusFound)
			})
			r.Post("/invitation/accept", h.FormInvitationAccept)
			r.Post("/invitations", h.FormInvitationCreate)
			r.Get("/invitations", h.FormInvitationsList)
			r.Delete("/invitations/{id}", h.FormInvitationRevoke)
			r.Get("/invitations/preview", h.InvitationPreview)
			r.Get("/admin/users", h.FormAdminUsersList)
			r.Post("/admin/users/{id}/suspend", h.FormAdminUserSuspend)
			r.Post("/admin/users/{id}/reactivate", h.FormAdminUserReactivate)
			r.Get("/admin/users/{id}/history", h.FormAdminUserAuthHistory)
			r.Get("/admin/users/{id}/audit-logs", h.FormAdminUserAuditLogsList)
			r.Post("/admin/roles", h.FormRoleCreate)
			r.Get("/admin/roles", h.FormRolesList)
			r.Delete("/admin/roles/{id}", h.FormRoleDelete)
			r.Post("/admin/permissions", h.FormPermissionCreate)
			r.Get("/admin/permissions", h.FormPermissionsList)
			r.Delete("/admin/permissions/{id}", h.FormPermissionDelete)
			r.Post("/admin/users/{id}/roles", h.FormUserRoleGrant)
			r.Get("/admin/users/{id}/roles", h.FormUserRolesList)
			r.Delete("/admin/users/{id}/roles/{role_name}", h.FormUserRoleRevoke)
			r.Post("/admin/roles/{name}/permissions", h.FormRolePermissionGrant)
			r.Delete("/admin/roles/{name}/permissions/{permission_name}", h.FormRolePermissionRevoke)
			r.Post("/admin/organizations", h.FormOrganizationCreate)
			r.Get("/admin/organizations", h.FormOrganizationsList)
			r.Get("/admin/organizations/{id}", h.FormOrganizationGetByID)
			r.Delete("/admin/organizations/{id}", h.FormOrganizationDelete)
			r.Post("/admin/organizations/{id}/members", h.FormOrgMemberAdd)
			r.Get("/admin/organizations/{id}/members", h.FormOrgMembersList)
			r.Delete("/admin/organizations/{id}/members/{user_id}", h.FormOrgMemberRemove)
			r.Get("/admin/users/{id}/organizations", h.FormUserOrganizationsList)
		})

		// Routes protected by API Key
		r.Group(func(r chi.Router) {
			r.Use(h.APIKeyMiddleware)

			// API Handlers (JSON)
			r.Route("/api", func(r chi.Router) {
				r.Post("/register", h.Register)
				r.Post("/login", h.Login)
				r.Post("/token/refresh", h.RefreshToken)
				r.Post("/password-reset/request", h.PasswordResetRequest)
				r.Post("/password-reset/confirm", h.PasswordResetConfirm)
				r.Get("/email-change/confirm", h.EmailChangeConfirm)
				r.Post("/passwordless/request", h.PasswordlessRequest)
				r.Get("/passwordless/login", h.PasswordlessLogin)
				r.Post("/sms-otp/request", h.SMSOTPRequest)
				r.Post("/sms-otp/verify", h.SMSOTPVerify)
				r.Post("/mfa/login/verify", h.MFALoginVerify)
				r.Post("/webauthn/login/begin", h.WebauthnLoginBegin)
				r.Post("/webauthn/login/finish", h.WebauthnLoginFinish)
				r.Post("/invitations/accept", h.InvitationAccept)
				r.Get("/invitations/preview", h.InvitationPreview)

				// Protected routes
				r.Group(func(r chi.Router) {
					r.Use(h.AuthMiddleware)
					r.Get("/userinfo", h.UserInfo)
					r.Post("/logout", h.Logout)
					r.Post("/impersonate", h.Impersonate)
					r.Post("/impersonate/stop", h.StopImpersonation)
					r.Delete("/user", h.DeleteUser)
					r.Post("/mfa/enroll", h.MFAEnroll)
					r.Post("/mfa/confirm", h.MFAConfirm)
					r.Post("/mfa/disable", h.MFADisable)
					r.Post("/webauthn/register/begin", h.WebauthnRegisterBegin)
					r.Post("/webauthn/register/finish", h.WebauthnRegisterFinish)
					r.Get("/webauthn/credentials", h.WebauthnCredentialsList)
					r.Delete("/webauthn/credentials/{id}", h.WebauthnCredentialDelete)
					r.Get("/trusted-devices", h.TrustedDevicesList)
					r.Delete("/trusted-devices/{id}", h.TrustedDeviceRevoke)
					r.Get("/sessions", h.SessionsList)
					r.Delete("/sessions/{id}", h.SessionRevoke)
					r.Delete("/sessions", h.SessionsRevokeAll)
					r.Post("/api-keys", h.APIKeyCreate)
					r.Get("/api-keys", h.APIKeysList)
					r.Delete("/api-keys/{id}", h.APIKeyRevoke)
					r.Post("/invitations", h.InvitationCreate)
					r.Get("/invitations", h.InvitationsList)
					r.Delete("/invitations/{id}", h.InvitationRevoke)
					r.Post("/email-change/request", h.EmailChangeRequest)
					r.Get("/admin/users", h.AdminUsersList)
					r.Post("/admin/users/{id}/suspend", h.AdminUserSuspend)
					r.Post("/admin/users/{id}/reactivate", h.AdminUserReactivate)
					r.Get("/admin/users/{id}/history", h.AdminUserAuthHistory)
					r.Get("/admin/users/{id}/audit-logs", h.AdminUserAuditLogsList)
					r.Post("/admin/roles", h.RoleCreate)
					r.Get("/admin/roles", h.RolesList)
					r.Delete("/admin/roles/{id}", h.RoleDelete)
					r.Post("/admin/permissions", h.PermissionCreate)
					r.Get("/admin/permissions", h.PermissionsList)
					r.Delete("/admin/permissions/{id}", h.PermissionDelete)
					r.Post("/admin/users/{id}/roles", h.UserRoleGrant)
					r.Get("/admin/users/{id}/roles", h.UserRolesList)
					r.Delete("/admin/users/{id}/roles/{role_name}", h.UserRoleRevoke)
					r.Post("/admin/roles/{name}/permissions", h.RolePermissionGrant)
					r.Delete("/admin/roles/{name}/permissions/{permission_name}", h.RolePermissionRevoke)
					r.Post("/admin/organizations", h.OrganizationCreate)
					r.Get("/admin/organizations", h.OrganizationsList)
					r.Get("/admin/organizations/{id}", h.OrganizationGetByID)
					r.Delete("/admin/organizations/{id}", h.OrganizationDelete)
					r.Post("/admin/organizations/{id}/members", h.OrgMemberAdd)
					r.Get("/admin/organizations/{id}/members", h.OrgMembersList)
					r.Delete("/admin/organizations/{id}/members/{user_id}", h.OrgMemberRemove)
					r.Get("/admin/users/{id}/organizations", h.UserOrganizationsList)
				})
			})
		})
	})

	return h
}

// Run starts the HTTP server with conservative timeouts and blocks until it
// receives SIGINT/SIGTERM, at which point it stops accepting new connections
// and drains in-flight requests (up to defaultShutdownTimeout) before
// returning.
func (h *Handler) Run() {
	srv := &http.Server{
		Addr:              h.svc.Cfg.Addr,
		Handler:           h.r,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		xlog.Info("server started", "addr", h.svc.Cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			log.Fatal(err)
		}
	case <-ctx.Done():
		stop()
		xlog.Info("shutdown signal received, draining in-flight requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			xlog.Error("graceful shutdown failed", "error", err)
		}
		<-serveErr
	}
}

// ServeHTTP implements the http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.r.ServeHTTP(w, r)
}
