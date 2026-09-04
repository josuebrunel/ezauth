package middleware

import "errors"

var (
	ErrAuthorizationHeaderRequired = errors.New("authorization header required")
	ErrBearerTokenRequired         = errors.New("bearer token required")
	ErrUnexpectedSigningMethod     = errors.New("unexpected signing method")
	ErrInvalidToken                = errors.New("invalid token")
	ErrInvalidTokenClaims          = errors.New("invalid token claims")
	ErrAPIKeyRequired              = errors.New("x-api-key header required") // Matches original text
	ErrInvalidAPIKey               = errors.New("invalid api key")
	ErrUnauthorized                = errors.New("unauthorized")
	ErrForbidden                   = errors.New("forbidden")
)
