package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// DeviceTokenHeader is the request header a JSON API client sends its stored
// trusted-device token back on, so Login can skip MFA step-up for that device.
// MFALoginVerify/FormMFALoginVerify return a fresh value to store when
// remember_device is requested.
const DeviceTokenHeader = "X-Device-Token"

// TrustedDevicesList lists the authenticated user's trusted devices.
// @Summary List trusted devices
// @Tags mfa
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]service.TrustedDeviceInfo]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/trusted-devices [get]
func (h *Handler) TrustedDevicesList(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}

	devices, err := h.svc.TrustedDevices(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, devices, nil)
}

// TrustedDeviceRevoke revokes one of the authenticated user's trusted devices.
// @Summary Revoke a trusted device
// @Tags mfa
// @Produce json
// @Param id path string true "Trusted device record ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/trusted-devices/{id} [delete]
func (h *Handler) TrustedDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.RevokeTrustedDevice(r.Context(), user, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "trusted device revoked"}, nil)
}

// FormTrustedDevicesList lists the current session user's trusted devices.
func (h *Handler) FormTrustedDevicesList(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	devices, err := h.svc.TrustedDevices(r.Context(), user.ID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, devices, nil)
}

// FormTrustedDeviceRevoke revokes one of the current session user's trusted devices.
func (h *Handler) FormTrustedDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.RevokeTrustedDevice(r.Context(), user, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "trusted device revoked"}, nil)
}
