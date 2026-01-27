package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

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
