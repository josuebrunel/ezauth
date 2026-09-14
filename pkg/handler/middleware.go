package handler

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/handler/middleware"
)

// AuthMiddleware is a middleware that authenticates requests using a JWT bearer token.
// When Cfg.JWT.Issuer/Audience are configured, tokens are additionally
// required to carry a matching iss/aud claim (see #207).
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	var opts []jwt.ParserOption
	if h.svc.Cfg.JWT.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(h.svc.Cfg.JWT.Issuer))
	}
	if h.svc.Cfg.JWT.Audience != "" {
		opts = append(opts, jwt.WithAudience(h.svc.Cfg.JWT.Audience))
	}
	return middleware.AuthMiddleware(h.svc.JWTKeyFunc(), h.svc.JWTSigningMethods(), h.svc.Repo, opts...)(next)
}

// APIKeyMiddleware checks for a valid API key in the X-API-Key header.
func (h *Handler) APIKeyMiddleware(next http.Handler) http.Handler {
	return middleware.APIKeyMiddleware(h.svc.Cfg.ApiKey, h.svc.Repo, h.svc.Repo)(next)
}

// RequireAPIKeyScope is a middleware that requires the API key used to
// authenticate the request (via APIKeyMiddleware, which must run upstream)
// to include the given scope.
func (h *Handler) RequireAPIKeyScope(scope string) func(http.Handler) http.Handler {
	return middleware.RequireAPIKeyScope(scope)
}

// RequireRole is a middleware that requires the authenticated user to hold
// the given role, checked against the RBAC roles/permissions tables.
func (h *Handler) RequireRole(role string) func(http.Handler) http.Handler {
	return middleware.RequireRole(h.svc, role)
}

// RequirePermission is a middleware that requires the authenticated user to
// hold the given permission, checked against the RBAC roles/permissions
// tables.
func (h *Handler) RequirePermission(permission string) func(http.Handler) http.Handler {
	return middleware.RequirePermission(h.svc, permission)
}

// RequireOrgMembership is a middleware that requires the authenticated user
// to be a member of the "current organization" (set by an OrgLoaderMiddleware
// mounted upstream) -- see middleware.RequireOrgMembership.
func (h *Handler) RequireOrgMembership(next http.Handler) http.Handler {
	return middleware.RequireOrgMembership(h.svc)(next)
}

// RequireOrgRole is a middleware that requires the authenticated user's role
// within the "current organization" (set by an OrgLoaderMiddleware mounted
// upstream) to equal role -- see middleware.RequireOrgRole.
func (h *Handler) RequireOrgRole(role string) func(http.Handler) http.Handler {
	return middleware.RequireOrgRole(h.svc, role)
}

// LoginRequiredMiddleware is a middleware that requires the request to be authenticated.
// If the user is not authenticated, it redirects to the login page (for browser requests)
// or returns a 401 Unauthorized error (for API requests).
func (h *Handler) LoginRequiredMiddleware(next http.Handler) http.Handler {
	return middleware.LoginRequiredMiddleware(h, h.svc.Cfg.Pages.Login)(next)
}
