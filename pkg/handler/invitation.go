package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

// InvitationCreate issues a new invitation on behalf of the authenticated user.
// @Summary Create an invitation
// @Description Emails an invitee a link to accept an invitation and complete registration
// @Tags invitation
// @Accept json
// @Produce json
// @Param request body service.RequestInvitation true "Invitation Request"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.InvitationInfo]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/invitations [post]
func (h *Handler) InvitationCreate(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	inviter, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	var req service.RequestInvitation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	info, err := h.svc.InvitationCreate(r.Context(), inviter, req)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, info, nil)
}

// InvitationsList lists the invitations issued by the authenticated user.
// @Summary List invitations
// @Tags invitation
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]service.InvitationInfo]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/invitations [get]
func (h *Handler) InvitationsList(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}

	invitations, err := h.svc.Invitations(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, invitations, nil)
}

// InvitationRevoke revokes one of the authenticated user's invitations.
// @Summary Revoke an invitation
// @Tags invitation
// @Produce json
// @Param id path string true "Invitation record ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/invitations/{id} [delete]
func (h *Handler) InvitationRevoke(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	inviter, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvitationIDRequired)
		return
	}

	if err := h.svc.InvitationRevoke(r.Context(), inviter, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "invitation revoked"}, nil)
}

// InvitationPreview looks up a pending invitation by its token, e.g. to
// prefill a registration form. It does not require authentication.
// @Summary Preview an invitation
// @Tags invitation
// @Produce json
// @Param token query string true "Invitation token"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.InvitationInfo]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/invitations/preview [get]
func (h *Handler) InvitationPreview(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvitationTokenRequired)
		return
	}

	info, err := h.svc.InvitationPreview(r.Context(), token)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, info, nil)
}

// InvitationAccept completes registration for an invitation.
// @Summary Accept an invitation
// @Description Creates the invitee's account with the invitation's pre-verified email and roles, and returns session tokens
// @Tags invitation
// @Accept json
// @Produce json
// @Param request body service.RequestInvitationAccept true "Invitation Accept Request"
// @Security ApiKeyAuth
// @Success 201 {object} ApiResponse[service.TokenResponse]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/invitations/accept [post]
func (h *Handler) InvitationAccept(w http.ResponseWriter, r *http.Request) {
	var req service.RequestInvitationAccept
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}
	if req.Token == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvitationTokenRequired)
		return
	}

	if preview, err := h.svc.InvitationPreview(r.Context(), req.Token); err == nil {
		hookUser := &models.User{Email: preview.Email, Username: req.Username, FirstName: req.FirstName, LastName: req.LastName, Roles: preview.Roles}
		if err := h.svc.Hook.BeforeUserCreated(r.Context(), hookUser); err != nil {
			WriteJSONResponseError(w, http.StatusBadRequest, err)
			return
		}
	}

	createdUser, tokenResp, err := h.svc.InvitationAccept(r.Context(), req)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.svc.Hook.AfterUserCreated(r.Context(), createdUser); err != nil {
		xlog.Error("hook AfterUserCreated failed", "user_id", createdUser.ID, "err", err)
	}
	if err := h.svc.Hook.AfterUserSignedIn(r.Context(), createdUser); err != nil {
		xlog.Error("hook AfterUserSignedIn failed", "user_id", createdUser.ID, "err", err)
	}

	WriteJSONResponse(w, http.StatusCreated, tokenResp, nil)
}
