package handler

import (
	"encoding/json"
	"net/http"

	"github.com/josuebrunel/ezauth/pkg/service"
)

// EmailChangeRequest initiates a guarded email change for the authenticated
// user, requiring their current password.
// @Summary Request an email change
// @Description Verifies the current password, then emails a confirmation link to the new address
// @Tags user
// @Accept json
// @Produce json
// @Param request body service.RequestEmailChange true "Email Change Request"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/email-change/request [post]
func (h *Handler) EmailChangeRequest(w http.ResponseWriter, r *http.Request) {
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

	var req service.RequestEmailChange
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.EmailChangeRequest(r.Context(), user, req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "confirmation email sent to the new address"}, nil)
}

// EmailChangeConfirm completes a guarded email change.
// @Summary Confirm an email change
// @Description Applies the requested email change and revokes other sessions
// @Tags user
// @Produce json
// @Param token query string true "Email change token"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.User]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/email-change/confirm [get]
func (h *Handler) EmailChangeConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrTokenRequired)
		return
	}

	user, err := h.svc.EmailChangeConfirm(r.Context(), token)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	user.Sanitize()
	WriteJSONResponse(w, http.StatusOK, user, nil)
}
