// Package handler provides the HTTP handlers for ezauth.
package handler

import (
	"encoding/gob"
	"log"
	"net/http"
	"strings"

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

// LoadUserMiddleware is a middleware that loads the authenticated user into the context.
// This allows downstream handlers to use GetSessionUser(ctx) without the Handler instance.
func (h *Handler) LoadUserMiddleware(next http.Handler) http.Handler {
	return ezmiddleware.LoadUserMiddleware(h.GetSessionUser)(next)
}

// SessionMiddleware combines LoadAndSave and LoadUserMiddleware.
// It ensures session data is loaded/saved and the user is populated in the context.
func (h *Handler) SessionMiddleware(next http.Handler) http.Handler {
	return ezmiddleware.SessionMiddleware(h.Session, h.GetSessionUser)(next)
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

	// Initialize Session Manager
	h.Session = scs.New()
	h.Session.Cookie.Name = "ezauthsess"
	h.Session.Cookie.HttpOnly = true
	h.Session.Cookie.Secure = strings.HasPrefix(h.svc.Cfg.BaseURL, "https://")
	h.Session.Cookie.Persist = true

	for _, opt := range options {
		opt(h)
	}

	// Default middlewares if router was newly created
	if len(options) == 0 {
		h.r.Use(middleware.Logger)
		h.r.Use(middleware.RequestID)
		h.r.Use(middleware.RealIP)
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
				xlog.Warn("CSRF_SECRET not set, falling back to JWT_SECRET. Set a dedicated EZAUTH_CSRF_SECRET for proper key separation.")
				csrfKey = h.svc.Cfg.JWTSecret
			}
			r.Use(csrf.Protect([]byte(csrfKey), csrf.Secure(strings.HasPrefix(h.svc.Cfg.BaseURL, "https://"))))

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
				r.Post("/passwordless/request", h.PasswordlessRequest)
				r.Get("/passwordless/login", h.PasswordlessLogin)
				r.Post("/sms-otp/request", h.SMSOTPRequest)
				r.Post("/sms-otp/verify", h.SMSOTPVerify)
				r.Post("/mfa/login/verify", h.MFALoginVerify)
				r.Post("/webauthn/login/begin", h.WebauthnLoginBegin)
				r.Post("/webauthn/login/finish", h.WebauthnLoginFinish)

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
				})
			})
		})
	})

	return h
}

// Run starts the HTTP server.
func (h *Handler) Run() {
	xlog.Info("server started", "addr", h.svc.Cfg.Addr)
	if err := http.ListenAndServe(h.svc.Cfg.Addr, h.r); err != nil {
		log.Fatal(err)
	}
}

// ServeHTTP implements the http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.r.ServeHTTP(w, r)
}
