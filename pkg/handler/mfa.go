package handler

import (
	"encoding/json"
	"net/http"

	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

type mfaConfirmRequest struct {
	Code string `json:"code"`
}

type mfaConfirmResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

type mfaLoginVerifyRequest struct {
	MFAToken       string `json:"mfa_token"`
	Code           string `json:"code"`
	RememberDevice bool   `json:"remember_device"`
}

type mfaLoginVerifyResponse struct {
	*service.TokenResponse
	DeviceToken string `json:"device_token,omitempty"`
}

// MFAEnroll begins TOTP enrollment for the authenticated user.
// @Summary Begin TOTP MFA enrollment
// @Description Generates a new TOTP secret for the authenticated user
// @Tags mfa
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.MFAEnrollResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/mfa/enroll [post]
func (h *Handler) MFAEnroll(w http.ResponseWriter, r *http.Request) {
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

	resp, err := h.svc.MFAEnroll(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, resp, nil)
}

// MFAConfirm confirms TOTP enrollment and enables MFA.
// @Summary Confirm TOTP MFA enrollment
// @Description Validates a TOTP code and enables MFA, returning one-time recovery codes
// @Tags mfa
// @Accept json
// @Produce json
// @Param request body mfaConfirmRequest true "MFA Confirm Request"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[mfaConfirmResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/mfa/confirm [post]
func (h *Handler) MFAConfirm(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ezmiddleware.UserContextKey).(string)
	if !ok {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrUserNotFoundInContext)
		return
	}

	var req mfaConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}
	if req.Code == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrMFACodeRequired)
		return
	}

	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	codes, err := h.svc.MFAConfirm(r.Context(), user, req.Code)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.svc.Hook.AfterMFAEnabled(r.Context(), user); err != nil {
		xlog.Error("hook AfterMFAEnabled failed", "user_id", user.ID, "err", err)
	}

	WriteJSONResponse(w, http.StatusOK, mfaConfirmResponse{RecoveryCodes: codes}, nil)
}

// MFADisable disables TOTP MFA for the authenticated user.
// @Summary Disable TOTP MFA
// @Description Validates a TOTP or recovery code and disables MFA
// @Tags mfa
// @Accept json
// @Produce json
// @Param request body mfaConfirmRequest true "MFA Disable Request"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/mfa/disable [post]
func (h *Handler) MFADisable(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ezmiddleware.UserContextKey).(string)
	if !ok {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrUserNotFoundInContext)
		return
	}

	var req mfaConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}
	if req.Code == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrMFACodeRequired)
		return
	}

	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	if err := h.svc.MFADisable(r.Context(), user, req.Code); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.svc.Hook.AfterMFADisabled(r.Context(), user); err != nil {
		xlog.Error("hook AfterMFADisabled failed", "user_id", user.ID, "err", err)
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "mfa disabled"}, nil)
}

// MFALoginVerify completes a step-up login started by Login when MFA is required.
// If remember_device is true, the response also carries a device_token; sending
// it back via the X-Device-Token header on a future Login skips this step-up.
// @Summary Complete MFA step-up login
// @Description Exchanges an mfa_token and TOTP/recovery code for session tokens
// @Tags mfa
// @Accept json
// @Produce json
// @Param request body mfaLoginVerifyRequest true "MFA Login Verify Request"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[mfaLoginVerifyResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 401 {object} ApiResponse[string]
// @Router /auth/api/mfa/login/verify [post]
func (h *Handler) MFALoginVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaLoginVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}
	if req.MFAToken == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrMFATokenRequired)
		return
	}
	if req.Code == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrMFACodeRequired)
		return
	}

	user, tokenResp, deviceToken, err := h.svc.MFALoginVerify(r.Context(), req.MFAToken, req.Code, req.RememberDevice)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, err)
		return
	}

	if err := h.svc.Hook.AfterUserSignedIn(r.Context(), user); err != nil {
		xlog.Error("hook AfterUserSignedIn failed", "user_id", user.ID, "err", err)
	}

	WriteJSONResponse(w, http.StatusOK, mfaLoginVerifyResponse{TokenResponse: tokenResp, DeviceToken: deviceToken}, nil)
}
