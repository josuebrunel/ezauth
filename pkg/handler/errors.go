package handler

import "errors"

var (
	ErrInvalidRequestBody         = errors.New("invalid request body")
	ErrRefreshTokenRequired      = errors.New("refresh_token is required")
	ErrTokenRequired             = errors.New("token is required")
	ErrUserNotFoundInContext      = errors.New("could not retrieve user from context")
	ErrInvalidToken              = errors.New("invalid token")
	ErrInvalidTokenClaims        = errors.New("invalid token claims")
	ErrBearerTokenRequired       = errors.New("bearer token required")
	ErrAuthorizationHeaderRequired = errors.New("authorization header required")
	ErrCouldNotCreateToken       = errors.New("could not create token")
	ErrCouldNotCreateUser        = errors.New("could not create user")
	ErrInvalidCredentials        = errors.New("invalid email or password")
	ErrCouldNotRetrieveUser      = errors.New("could not retrieve user")
	ErrCouldNotRevokeToken       = errors.New("could not revoke token")
	ErrCouldNotDeleteUser        = errors.New("could not delete user")
	ErrCouldNotProcessPasswordReset = errors.New("could not process password reset request")
	ErrCouldNotProcessPasswordless = errors.New("could not process passwordless request")
	ErrUserIDNotFoundInContext   = errors.New("user id not found in context")
	ErrUnexpectedSigningMethod   = errors.New("unexpected signing method")
)
