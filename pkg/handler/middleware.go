package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// AuthMiddleware is a middleware that authenticates requests using a JWT bearer token.
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrAuthorizationHeaderRequired)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrBearerTokenRequired)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedSigningMethod
			}
			return []byte(h.svc.Cfg.JWTSecret), nil
		})

		if err != nil {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidToken)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidToken)
			return
		}

		userID, ok := claims["sub"].(string)
		if !ok {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidTokenClaims)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// APIKeyMiddleware checks for a valid API key in the X-API-Key header.
func (h *Handler) APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrAPIKeyRequired)
			return
		}

		// Check against config first
		if apiKey == h.svc.Cfg.ApiKey {
			next.ServeHTTP(w, r)
			return
		}

		// Check against database
		token, err := h.svc.Repo.TokenGetByToken(r.Context(), apiKey)
		if err != nil {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
			return
		}

		if token.TokenType != models.TokenTypeApiKey {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
			return
		}

		if token.Revoked {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
			return
		}

		if !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(time.Now()) {
			WriteJSONResponseError(w, http.StatusUnauthorized, ErrInvalidAPIKey)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// LoginRequired is a middleware that checks if the request is authenticated.
// If the user is not authenticated, it redirects to the login page (for browser requests)
// or returns a 401 Unauthorized error (for API requests).
func (h *Handler) LoginRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.IsAuthenticated(r.Context()) {
			// Check if it's an API request (JSON) or a browser request
			// We can check the Accept header or the path prefix
			// For simplicity, let's assume /api/ paths are JSON
			if strings.HasPrefix(r.URL.Path, "/auth/api") || strings.Contains(r.Header.Get("Accept"), "application/json") {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
				return
			}

			// redirect to login
			http.Redirect(w, r, h.svc.Cfg.Pages.Login, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
