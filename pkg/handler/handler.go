package handler

import (
	"context"
	"encoding/json"
	"errors"
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

type Handler struct {
	path string
	r    *chi.Mux
	svc  *service.Auth
}

func New(svc *service.Auth, path string) *Handler {
	r := chi.NewRouter()

	h := &Handler{
		path: path,
		r:    r,
		svc:  svc,
	}

	// Initialize middlewares
	h.r.Use(middleware.Logger)
	h.r.Use(middleware.RequestID)
	h.r.Use(middleware.RealIP)
	h.r.Use(middleware.Recoverer)

	h.r.Get("/ping", h.Ping)

	// Initialize routes
	h.r.Route("/"+h.path, func(r chi.Router) {
		// Public routes
		r.Post("/register", h.Register)
		r.Post("/login", h.Login)
		r.Post("/token/refresh", h.RefreshToken)

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

func (h *Handler) Run() {
	xlog.Info("server started", "addr", h.svc.Cfg.Addr)
	if err := http.ListenAndServe(h.svc.Cfg.Addr, h.r); err != nil {
		log.Fatal(err)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.r.ServeHTTP(w, r)
}

func GetUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(userContextKey).(string)
	if !ok {
		return "", errors.New("user id not found in context")
	}
	return userID, nil
}

func (h *Handler) Ping(w http.ResponseWriter, r *http.Request) {
	WriteJSONResponse(w, http.StatusOK, "pong", nil)
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req service.RequestBasicAuth
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	user, err := h.svc.UserCreate(r.Context(), &req)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not create user"))
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not create token"))
		return
	}

	WriteJSONResponse(w, http.StatusCreated, tokenResp, nil)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req service.RequestBasicAuth
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	user, err := h.svc.UserAuthenticate(r.Context(), req)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, errors.New("invalid email or password"))
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not create token"))
		return
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.RefreshToken == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, errors.New("refresh_token is required"))
		return
	}

	tokenResp, err := h.svc.TokenRefresh(r.Context(), req.RefreshToken)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not retrieve user from context"))
		return
	}

	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not retrieve user"))
		return
	}

	user.PasswordHash = ""
	WriteJSONResponse(w, http.StatusOK, user, nil)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}

	if req.RefreshToken == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, errors.New("refresh_token is required"))
		return
	}

	if err := h.svc.TokenRevoke(r.Context(), req.RefreshToken); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not revoke token"))
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "logged out successfully"}, nil)
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(userContextKey).(string)
	if !ok {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not retrieve user from context"))
		return
	}

	if err := h.svc.Repo.UserDelete(r.Context(), userID); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, errors.New("could not delete user"))
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "user deleted successfully"}, nil)
}
