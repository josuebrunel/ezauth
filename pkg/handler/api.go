package handler

import (
	"context"
	"encoding/json"
	"net/http"

	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
)

// GetUserID retrieves the user ID from the request context.
// It returns ErrUserIDNotFoundInContext if the user ID is not present.
func GetUserID(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(ezmiddleware.UserContextKey).(string)
	if !ok {
		return "", ErrUserIDNotFoundInContext
	}
	return userID, nil
}

// Ping is a simple health check endpoint.
// @Summary Ping health check
// @Description Checks if the server is running
// @Tags system
// @Success 200 {object} ApiResponse[string]
// @Router /ping [get]
func (h *Handler) Ping(w http.ResponseWriter, r *http.Request) {
	WriteJSONResponse(w, http.StatusOK, "pong", nil)
}

// Register handles user registration.
// @Summary Register a new user
// @Description Register a new user with basic authentication
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RequestBasicAuth true "Registration Request"
// @Security ApiKeyAuth
// @Success 201 {object} ApiResponse[service.TokenResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/register [post]
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
// @Summary Login user
// @Description Login with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RequestBasicAuth true "Login Request"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.TokenResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 401 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/login [post]
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

	_ = service.CallHook(h.svc.Hooks.OnUserSignedIn, r.Context(), user)

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotCreateToken)
		return
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}

// RefreshToken handles token refreshing using a valid refresh token.
// @Summary Refresh access token
// @Description Get a new access token using a refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh Token Request"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.TokenResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 401 {object} ApiResponse[string]
// @Router /auth/token/refresh [post]
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
// @Summary Get user info
// @Description Retrieve information about the authenticated user
// @Tags user
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.User]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/userinfo [get]
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ezmiddleware.UserContextKey).(string)
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
// @Summary Logout user
// @Description Revoke the user's refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LogoutRequest true "Logout Request"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/logout [post]
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

	if userID, err := GetUserID(r.Context()); err == nil {
		if user, err := h.svc.Repo.UserGetByID(r.Context(), userID); err == nil {
			_ = service.CallHook(h.svc.Hooks.OnUserSignedOut, r.Context(), user)
		}
	}

	if err := h.svc.TokenRevoke(r.Context(), req.RefreshToken); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRevokeToken)
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "logged out successfully"}, nil)
}

// DeleteUser handles user account deletion.
// @Summary Delete user
// @Description Delete the authenticated user's account
// @Tags user
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/user [delete]
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ezmiddleware.UserContextKey).(string)
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
// @Summary Request password reset
// @Description Send a password reset link to the user's email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RequestPasswordReset true "Password Reset Request"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/password-reset/request [post]
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
// @Summary Confirm password reset
// @Description Reset password using the token sent via email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RequestPasswordResetConfirm true "Password Reset Confirmation"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/password-reset/confirm [post]
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
// @Summary Request magic link
// @Description Send a magic login link to the user's email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RequestPasswordless true "Passwordless Request"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/passwordless/request [post]
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
// @Summary Magic link login
// @Description Authenticate using the token from the magic link
// @Tags auth
// @Produce json
// @Param token query string true "Magic Link Token"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.TokenResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 401 {object} ApiResponse[string]
// @Router /auth/passwordless/login [get]
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
