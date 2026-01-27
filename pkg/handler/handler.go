// Package handler provides the HTTP handlers for ezauth.
package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

type contextKey string

const userContextKey = contextKey("userID")

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Handler handles all authentication-related HTTP requests.
type Handler struct {
	path string
	r    *chi.Mux
	svc  *service.Auth
}

// HandlerOption defines a functional option for configuring the Handler.
type HandlerOption func(*Handler)

// WithRouter sets a custom chi router for the Handler.
func WithRouter(r *chi.Mux) HandlerOption {
	return func(h *Handler) {
		h.r = r
	}
}

// New creates a new Handler with the given service and path.
// path is the base URL path where the authentication routes will be mounted.
func New(svc *service.Auth, path string, options ...HandlerOption) *Handler {
	h := &Handler{
		path: path,
		r:    chi.NewRouter(),
		svc:  svc,
	}

	for _, opt := range options {
		opt(h)
	}

	// Default middlewares if router was newly created
	if len(options) == 0 {
		h.r.Use(middleware.Logger)
		h.r.Use(middleware.RequestID)
		h.r.Use(middleware.RealIP)
		h.r.Use(middleware.Recoverer)
	}

	h.r.Get("/ping", h.Ping)

	// Initialize routes
	routePath := "/" + h.path
	if h.path == "" {
		routePath = "/"
	}
	h.r.Route(routePath, func(r chi.Router) {
		// Public routes
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Post("/token/refresh", h.RefreshToken)
		r.Post("/password-reset/request", h.PasswordResetRequest)
		r.Post("/password-reset/confirm", h.PasswordResetConfirm)
		r.Post("/passwordless/request", h.PasswordlessRequest)
		r.Get("/passwordless/login", h.PasswordlessLogin)
		r.Get("/oauth2/{provider}/login", h.OAuth2Login)
		r.Get("/oauth2/{provider}/callback", h.OAuth2Callback)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(h.AuthMiddleware)
			r.Get("/userinfo", h.UserInfo)
			r.Post("/logout", h.Logout)
			r.Delete("/user", h.DeleteUser)
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

// GetUserID retrieves the user ID from the request context.
// It returns ErrUserIDNotFoundInContext if the user ID is not present.
func GetUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(userContextKey).(string)
	if !ok {
		return "", ErrUserIDNotFoundInContext
	}
	return userID, nil
}

// Ping is a simple health check endpoint.
func (h *Handler) Ping(w http.ResponseWriter, r *http.Request) {
	WriteJSONResponse(w, http.StatusOK, "pong", nil)
}

// Register handles user registration.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req service.RequestBasicAuth
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	user, err := h.svc.UserCreate(r.Context(), &req)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotCreateUser)
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotCreateToken)
		return
	}

	WriteJSONResponse(w, http.StatusCreated, tokenResp, nil)
}

// Login handles user login and returns access and refresh tokens.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req service.RequestBasicAuth
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	user, err := h.svc.UserAuthenticate(r.Context(), req)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidCredentials)
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotCreateToken)
		return
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}

// RefreshToken handles token refreshing using a valid refresh token.
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if req.RefreshToken == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrRefreshTokenRequired)
		return
	}

	tokenResp, err := h.svc.TokenRefresh(r.Context(), req.RefreshToken)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}

// UserInfo returns information about the currently authenticated user.
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrUserNotFoundInContext)
		return
	}

	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	user.PasswordHash = ""
	WriteJSONResponse(w, http.StatusOK, user, nil)
}

// Logout handles user logout by revoking the refresh token.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if req.RefreshToken == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrRefreshTokenRequired)
		return
	}

	if err := h.svc.TokenRevoke(r.Context(), req.RefreshToken); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRevokeToken)
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "logged out successfully"}, nil)
}

// DeleteUser handles user account deletion.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrUserNotFoundInContext)
		return
	}

	if err := h.svc.Repo.UserDelete(r.Context(), userID); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotDeleteUser)
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "user deleted successfully"}, nil)
}

// PasswordResetRequest handles the request for a password reset link.
func (h *Handler) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req service.RequestPasswordReset
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.PasswordResetRequest(r.Context(), req); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotProcessPasswordReset)
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "password reset link sent"}, nil)
}

// PasswordResetConfirm handles the confirmation of a password reset.
func (h *Handler) PasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req service.RequestPasswordResetConfirm
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.PasswordResetConfirm(r.Context(), req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "password has been reset successfully"}, nil)
}

// PasswordlessRequest handles the request for a magic login link.
func (h *Handler) PasswordlessRequest(w http.ResponseWriter, r *http.Request) {
	var req service.RequestPasswordless
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.PasswordlessRequest(r.Context(), req); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotProcessPasswordless)
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "magic link sent"}, nil)
}

// PasswordlessLogin handles login using a magic link token.
func (h *Handler) PasswordlessLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrTokenRequired)
		return
	}

	tokenResp, err := h.svc.PasswordlessLogin(r.Context(), token)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}
