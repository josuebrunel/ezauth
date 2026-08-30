package handler

import (
	"encoding/json"
	"net/http"

	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

// SMSOTPRequest handles the request for an SMS one-time login code.
// @Summary Request SMS OTP
// @Description Send a one-time login code to the user's phone number
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RequestSMSOTP true "SMS OTP Request"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/sms-otp/request [post]
func (h *Handler) SMSOTPRequest(w http.ResponseWriter, r *http.Request) {
	var req service.RequestSMSOTP
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.SMSOTPRequest(r.Context(), req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "verification code sent"}, nil)
}

// SMSOTPVerify handles login via an SMS one-time code.
// @Summary Verify SMS OTP
// @Description Authenticate using the one-time code sent via SMS
// @Tags auth
// @Accept json
// @Produce json
// @Param request body service.RequestSMSOTPVerify true "SMS OTP Verify Request"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.TokenResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 401 {object} ApiResponse[string]
// @Router /auth/api/sms-otp/verify [post]
func (h *Handler) SMSOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req service.RequestSMSOTPVerify
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	tokenResp, err := h.svc.SMSOTPVerify(r.Context(), req)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, err)
		return
	}

	if user, err := h.svc.Repo.UserGetByPhone(r.Context(), req.Phone); err == nil {
		if err := h.svc.Hook.AfterUserSignedIn(r.Context(), user); err != nil {
			xlog.Error("hook AfterUserSignedIn failed", "user_id", user.ID, "err", err)
		}
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}
