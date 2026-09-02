package middleware

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// Common errors are now in errors.go

type contextKey string

const (
	UserContextKey         = contextKey("userID")
	UserObjectContextKey   = contextKey("user")
	ImpersonatorContextKey = contextKey("impersonatorID")
)

// UserLoader is a function that loads a user from context.
type UserLoader func(context.Context) (*models.User, error)

// AuthMiddleware is a middleware that authenticates requests using a JWT bearer token.
// keyFunc resolves the verification key for a token (see jwt.Keyfunc — e.g. by its
// "kid" header, to support asymmetric key rotation); validMethods restricts which
// signing algorithms are accepted (e.g. []string{"HS256"} or []string{"RS256"}),
// guarding against algorithm-confusion attacks.
func AuthMiddleware(keyFunc jwt.Keyfunc, validMethods []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
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

			token, err := jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods(validMethods))

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
			ctx := context.WithValue(r.Context(), UserContextKey, userID)
			if act, ok := claims["act"].(map[string]any); ok {
				if actorID, ok := act["sub"].(string); ok && actorID != "" {
					ctx = context.WithValue(ctx, ImpersonatorContextKey, actorID)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APIKeyMiddleware checks for a valid API key in the X-API-Key header.
func APIKeyMiddleware(configApiKey string, tokenRepo TokenGetter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				WriteJSONResponseError(w, http.StatusUnauthorized, ErrAPIKeyRequired)
				return
			}

			// Check against config first (constant-time comparison)
			if subtle.ConstantTimeCompare([]byte(apiKey), []byte(configApiKey)) == 1 {
				next.ServeHTTP(w, r)
				return
			}

			// Check against database
			token, err := tokenRepo.TokenGetByToken(r.Context(), apiKey)
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
}

// LoginRequiredMiddleware is a middleware that requires the request to be authenticated.
func LoginRequiredMiddleware(authChecker AuthChecker, loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authChecker.IsAuthenticated(r.Context()) {
				// Check if it's an API request (JSON) or a browser request
				if strings.HasPrefix(r.URL.Path, "/auth/api") || strings.Contains(r.Header.Get("Accept"), "application/json") {
					WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
					return
				}

				// redirect to login
				http.Redirect(w, r, loginPath, http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LoadUserMiddleware is a middleware that loads the authenticated user into the context.
func LoadUserMiddleware(loader UserLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if user, err := loader(ctx); err == nil {
				ctx = context.WithValue(ctx, UserContextKey, user.ID)
				ctx = context.WithValue(ctx, UserObjectContextKey, user)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoadAndSaveMiddleware uses the session manager
func LoadAndSaveMiddleware(sm *scs.SessionManager) func(http.Handler) http.Handler {
	return sm.LoadAndSave
}

// SessionMiddleware combines LoadAndSaveMiddleware and LoadUserMiddleware
func SessionMiddleware(sm *scs.SessionManager, loader UserLoader) func(http.Handler) http.Handler {
	return Chain(LoadAndSaveMiddleware(sm), LoadUserMiddleware(loader))
}

// Chain applies middlewares in order
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}
