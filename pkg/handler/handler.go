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

// formRequireAdminRole gates the Form admin/RBAC/org/impersonation
// subtree. It's the Form-route counterpart of the JSON API's default
// adminAuthz (RequireRole(svc, Cfg.AdminRole)), redirecting on failure
// instead of writing a JSON body, matching every other Form handler's
// convention -- unlike adminAuthz, it isn't overridable via WithAdminAuthz
// (see that option's doc comment for why) and always runs unless
// WithAdminAuthz(nil) disabled admin authorization entirely.
func (h *Handler) formRequireAdminRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := h.GetSessionUser(r.Context())
		if err != nil {
			h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrUnauthorized.Error())
			return
		}
		has, err := h.svc.UserHasRole(r.Context(), user.ID, h.svc.Cfg.AdminRole)
		if err != nil || !has {
			h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ezmiddleware.ErrForbidden.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
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

	// secureCookies is Cfg.ForceSecureCookies || strings.HasPrefix(Cfg.BaseURL,
	// "https://"), computed once in New() and reused for every cookie this
	// Handler sets (session, CSRF, oauth_state, trusted-device) so they all
	// agree -- a cookie that re-derived this from BaseURL alone would ignore
	// ForceSecureCookies.
	secureCookies bool

	// adminAuthz gates the admin/RBAC/org/impersonation route subtree (see
	// WithAdminAuthz). nil until New() resolves it to either an explicit
	// WithAdminAuthz value or the default RequireRole(svc, Cfg.AdminRole)
	// check; adminAuthzDisabled distinguishes "use the default" (both nil)
	// from "explicitly disabled via WithAdminAuthz(nil)".
	adminAuthz         func(http.Handler) http.Handler
	adminAuthzDisabled bool

	// customRouter is true once WithRouter has been applied, so New() can
	// tell "a caller passed WithAdminAuthz but not WithRouter" apart from
	// "a caller passed WithRouter" -- only the latter should skip the
	// default middleware chain. (Historically that check was len(options)
	// == 0, which broke the moment a second HandlerOption was introduced.)
	customRouter bool

	// swaggerAuthz gates /swagger/* (see WithSwaggerAuth). nil and
	// swaggerDisabled both false is the default: the route stays open,
	// matching every prior release. WithSwaggerAuth(nil) sets
	// swaggerDisabled instead, removing the route entirely.
	swaggerAuthz    func(http.Handler) http.Handler
	swaggerDisabled bool
}

// HandlerOption defines a functional option for configuring the Handler.
type HandlerOption func(*Handler)

// WithRouter sets a custom chi router for the Handler. New() skips its
// default middleware chain (logger, rate limiter, recoverer, ...) when this
// is used, since a caller supplying their own router is assumed to also
// want to control its middleware stack.
func WithRouter(r *chi.Mux) HandlerOption {
	return func(h *Handler) {
		h.r = r
		h.customRouter = true
	}
}

// WithAdminAuthz sets the middleware that gates the admin/RBAC/org route
// subtree (AdminUsersList/Suspend/Reactivate, RoleCreate/Delete,
// PermissionCreate/Delete, UserRoleGrant/Revoke, RolePermissionGrant/
// Revoke, OrganizationCreate/Delete, OrgMemberAdd/Remove) on both the JSON
// API and the Form routes -- both return a JSON body on an auth failure
// here (the Form ones did before #132 too, via an inline GetSessionUser
// check each handler already had), so one middleware shape covers both.
//
// Without this option, New() defaults to RequireRole(svc, Cfg.AdminRole)
// (Cfg.AdminRole defaults to "admin"), so those routes are denied unless the
// caller holds that RBAC role — see RoleCreate/UserRoleGrant, or the
// ezauthapi create-admin CLI subcommand, to grant it. Pass a custom
// middleware here instead for a different scheme (e.g. RequirePermission,
// an org-scoped check, or a check against your own authorization system) --
// it runs downstream of session/JWT/API-key/Form-session auth, so the
// caller's user ID is already in context (see RequireRole's doc comment for
// how to read it).
//
// Impersonate/StopImpersonation are the one exception: both transports
// gate them separately (formRequireAdminRole for the Form pair), always
// enforcing Cfg.AdminRole with no customization point, since
// FormImpersonate/FormStopImpersonation redirect (not JSON) on every other
// error path and a generic http.Handler middleware can't match that
// convention automatically. WithAdminAuthz's custom middleware has no
// effect on them; only WithAdminAuthz(nil) does (see below).
//
// Pass nil to explicitly disable the gate everywhere (JSON API, Form
// admin/RBAC/org, and Form impersonation alike), restoring the pre-#132
// behavior (any authenticated user reaches these routes) -- only do this if
// you're gating this subtree yourself at a layer in front of ezauth (e.g.
// an API gateway), since leaving it fully open otherwise is exactly the
// hole this option exists to close.
func WithAdminAuthz(mw func(http.Handler) http.Handler) HandlerOption {
	return func(h *Handler) {
		h.adminAuthz = mw
		h.adminAuthzDisabled = mw == nil
	}
}

// WithSwaggerAuth gates /swagger/* with mw. Without this option, the swagger
// UI (the full API surface/schema) is served with no authentication at all,
// matching every prior release -- set this in any deployment where that
// exposure isn't an explicit, intentional choice. Pass nil to remove the
// route entirely instead of gating it.
func WithSwaggerAuth(mw func(http.Handler) http.Handler) HandlerOption {
	return func(h *Handler) {
		h.swaggerAuthz = mw
		h.swaggerDisabled = mw == nil
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
	h.secureCookies = secureCookies

	// Initialize Session Manager
	h.Session = scs.New()
	h.Session.Cookie.Name = "ezauthsess"
	h.Session.Cookie.HttpOnly = true
	h.Session.Cookie.Secure = secureCookies
	h.Session.Cookie.Persist = true

	for _, opt := range options {
		opt(h)
	}

	// Resolve the admin/RBAC/org/impersonation authorization gate: an
	// explicit WithAdminAuthz wins (including WithAdminAuthz(nil), which
	// sets adminAuthzDisabled and leaves adminAuthz nil); otherwise default
	// to requiring Cfg.AdminRole via the RBAC tables. See WithAdminAuthz's
	// doc comment.
	//
	// Cfg.AdminRole's default:"admin" env tag only applies via LoadConfig;
	// a hand-built config.Config{} (bypassing LoadConfig, e.g. in tests, or
	// a library consumer constructing it directly) leaves it "" otherwise,
	// which would make the gate unsatisfiable by any role -- so fill it in
	// here too rather than repeating this footgun (see AccountLockout's
	// equivalent gap in service.New).
	if h.svc.Cfg.AdminRole == "" {
		h.svc.Cfg.AdminRole = "admin"
	}
	if h.adminAuthz == nil && !h.adminAuthzDisabled {
		h.adminAuthz = ezmiddleware.RequireRole(h.svc, h.svc.Cfg.AdminRole)
	}

	// sensitiveRateLimit gates the unauthenticated endpoints that create or
	// verify a short-lived credential (login, password reset, passwordless,
	// SMS OTP, MFA verification -- see sensitiveRateLimit's call sites
	// below), with its own budget independent of the general per-route
	// limiter mounted just below. Left a no-op when the router is
	// custom-built (matching the rest of this default middleware chain) so
	// WithRouter callers aren't handed rate limiting they didn't ask for.
	sensitiveRateLimit := func(next http.Handler) http.Handler { return next }

	// Default middlewares if router was newly created
	if !h.customRouter {
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

		// One shared limiter instance, not one per transport: a caller
		// spreading login/OTP attempts across the Form and JSON API
		// versions of the same endpoint should still exhaust a single
		// budget, not get a fresh one per transport.
		sensitiveRateLimit = ezmiddleware.NewRateLimiter(ezmiddleware.RateLimitConfig{
			Enabled:    h.svc.Cfg.RateLimit.SensitiveEnabled,
			Requests:   h.svc.Cfg.RateLimit.SensitiveRequests,
			Window:     h.svc.Cfg.RateLimit.SensitiveWindow,
			ByClientIP: h.svc.Cfg.RateLimit.ByClientIP,
		}).Middleware
	}

	h.r.Get("/ping", h.Ping)
	if !h.swaggerDisabled {
		if h.swaggerAuthz != nil {
			h.r.With(h.swaggerAuthz).Get("/swagger/*", httpSwagger.WrapHandler)
		} else {
			h.r.Get("/swagger/*", httpSwagger.WrapHandler)
		}
	}
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
			// CSRF Middleware. filippo.io/csrf/gorilla.Protect's authKey and
			// every Option except ErrorHandler/TrustedOrigins are ignored --
			// per its own doc comments ("authKey is ignored and can be
			// nil"; Secure is "Deprecated: ... does not rely on cookies").
			// The underlying filippo.io/csrf.Protection validates
			// Sec-Fetch-Site/Origin against Host, not an HMAC-signed token,
			// so there is no key to derive or separate from JWTSecret here
			// -- Cfg.CSRFSecret is accepted (and still redacted by
			// Sanitized()) only in case a future CSRF implementation swap
			// needs it again.
			r.Use(csrf.Protect(nil))

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
			r.With(sensitiveRateLimit).Post("/login", h.FormLogin)
			r.Post("/logout", h.FormLogout)
			r.With(sensitiveRateLimit).Post("/password-reset/request", h.FormPasswordResetRequest)
			r.With(sensitiveRateLimit).Post("/password-reset/confirm", h.FormPasswordResetConfirm)
			r.Post("/email-change/request", h.FormEmailChangeRequest)
			r.Get("/email-change/confirm", h.FormEmailChangeConfirm)
			r.With(sensitiveRateLimit).Post("/passwordless/request", h.FormPasswordlessRequest)
			r.With(sensitiveRateLimit).Get("/passwordless/login", h.FormPasswordlessLogin)
			r.With(sensitiveRateLimit).Post("/sms-otp/request", h.FormSMSOTPRequest)
			r.With(sensitiveRateLimit).Post("/sms-otp/verify", h.FormSMSOTPVerify)
			r.Get("/oauth2/{provider}/login", h.OAuth2Login)
			r.Get("/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, h.svc.Cfg.Pages.MFAVerify, http.StatusFound)
			})
			r.With(sensitiveRateLimit).Post("/mfa/login/verify", h.FormMFALoginVerify)
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

			// Impersonation: gated by formRequireAdminRole, which redirects
			// on failure like FormImpersonate/FormStopImpersonation's own
			// other error paths do -- unlike the rest of the Form
			// admin/RBAC/org routes just below, which (like the JSON API)
			// return a JSON body on failure. Not customizable via
			// WithAdminAuthz (see its doc comment for why), unless
			// WithAdminAuthz(nil) disabled admin authorization entirely.
			r.Group(func(r chi.Router) {
				if !h.adminAuthzDisabled {
					r.Use(h.formRequireAdminRole)
				}
				r.Post("/impersonate", h.FormImpersonate)
				r.Post("/impersonate/stop", h.FormStopImpersonation)
			})

			// Admin/RBAC/Org routes: these already return a JSON body (not
			// a redirect) on their own pre-existing auth failure, so they
			// share adminAuthz (see WithAdminAuthz) with the JSON API
			// instead of formRequireAdminRole. LoadUserMiddleware runs
			// first to populate the same UserContextKey adminAuthz's
			// default (RequireRole) reads -- Form routes don't run
			// AuthMiddleware.
			r.Group(func(r chi.Router) {
				r.Use(h.LoadUserMiddleware)
				if h.adminAuthz != nil {
					r.Use(h.adminAuthz)
				}
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
		})

		// Routes protected by API Key
		r.Group(func(r chi.Router) {
			r.Use(h.APIKeyMiddleware)

			// API Handlers (JSON)
			r.Route("/api", func(r chi.Router) {
				r.Post("/register", h.Register)
				r.With(sensitiveRateLimit).Post("/login", h.Login)
				r.Post("/token/refresh", h.RefreshToken)
				r.With(sensitiveRateLimit).Post("/password-reset/request", h.PasswordResetRequest)
				r.With(sensitiveRateLimit).Post("/password-reset/confirm", h.PasswordResetConfirm)
				r.Get("/email-change/confirm", h.EmailChangeConfirm)
				r.With(sensitiveRateLimit).Post("/passwordless/request", h.PasswordlessRequest)
				r.With(sensitiveRateLimit).Get("/passwordless/login", h.PasswordlessLogin)
				r.With(sensitiveRateLimit).Post("/sms-otp/request", h.SMSOTPRequest)
				r.With(sensitiveRateLimit).Post("/sms-otp/verify", h.SMSOTPVerify)
				r.With(sensitiveRateLimit).Post("/mfa/login/verify", h.MFALoginVerify)
				r.Post("/webauthn/login/begin", h.WebauthnLoginBegin)
				r.Post("/webauthn/login/finish", h.WebauthnLoginFinish)
				r.Post("/invitations/accept", h.InvitationAccept)
				r.Get("/invitations/preview", h.InvitationPreview)

				// Protected routes
				r.Group(func(r chi.Router) {
					r.Use(h.AuthMiddleware)
					r.Get("/userinfo", h.UserInfo)
					r.Post("/logout", h.Logout)
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

					// Admin/RBAC/Org/Impersonation routes: gated by
					// adminAuthz (see WithAdminAuthz), defaulting to
					// requiring Cfg.AdminRole. AuthMiddleware already ran
					// above, so UserContextKey -- what adminAuthz's default
					// (RequireRole) reads -- is already populated.
					r.Group(func(r chi.Router) {
						if h.adminAuthz != nil {
							r.Use(h.adminAuthz)
						}
						r.Post("/impersonate", h.Impersonate)
						r.Post("/impersonate/stop", h.StopImpersonation)
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
