package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			WriteJSONResponseError(w, http.StatusUnauthorized, errors.New("authorization header required"))
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			WriteJSONResponseError(w, http.StatusUnauthorized, errors.New("bearer token required"))
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(h.svc.Cfg.JWTSecret), nil
		})

		if err != nil {
			WriteJSONResponseError(w, http.StatusUnauthorized, errors.New("invalid token"))
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			WriteJSONResponseError(w, http.StatusUnauthorized, errors.New("invalid token"))
			return
		}

		userID, ok := claims["sub"].(string)
		if !ok {
			WriteJSONResponseError(w, http.StatusUnauthorized, errors.New("invalid token claims"))
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
