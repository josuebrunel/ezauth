package handler

import (
	"net/http"

	"github.com/josuebrunel/ezauth/pkg/handler/middleware"
)

// AuthMiddleware is a middleware that authenticates requests using a JWT bearer token.
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return middleware.AuthMiddleware(h.svc.Cfg.JWTSecret)(next)
}

// APIKeyMiddleware checks for a valid API key in the X-API-Key header.
func (h *Handler) APIKeyMiddleware(next http.Handler) http.Handler {
	return middleware.APIKeyMiddleware(h.svc.Cfg.ApiKey, h.svc.Repo)(next)
}

// LoginRequiredMiddleware is a middleware that requires the request to be authenticated.
// If the user is not authenticated, it redirects to the login page (for browser requests)
// or returns a 401 Unauthorized error (for API requests).
func (h *Handler) LoginRequiredMiddleware(next http.Handler) http.Handler {
	return middleware.LoginRequiredMiddleware(h, h.svc.Cfg.Pages.Login)(next)
}
