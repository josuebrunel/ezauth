package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// SessionsList lists the authenticated user's active sessions (one per
// logged-in device/client).
// @Summary List active sessions
// @Tags sessions
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]service.SessionInfo]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/sessions [get]
func (h *Handler) SessionsList(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}

	sessions, err := h.svc.Sessions(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, sessions, nil)
}

// SessionRevoke revokes one of the authenticated user's active sessions,
// logging that device out immediately.
// @Summary Revoke a session
// @Tags sessions
// @Produce json
// @Param id path string true "Session record ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/sessions/{id} [delete]
func (h *Handler) SessionRevoke(w http.ResponseWriter, r *http.Request) {
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
	if err := h.svc.RevokeSession(r.Context(), user, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "session revoked"}, nil)
}

// SessionsRevokeAll revokes all of the authenticated user's active sessions
// except the current one, i.e. "log out other devices". The current session
// is identified by the "except" query parameter (a session record ID from
// SessionsList); omit it to log out everywhere, including this device.
// @Summary Revoke all other sessions
// @Tags sessions
// @Produce json
// @Param except query string false "Session record ID to keep (e.g. the caller's current session)"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/sessions [delete]
func (h *Handler) SessionsRevokeAll(w http.ResponseWriter, r *http.Request) {
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

	except := r.URL.Query().Get("except")
	if err := h.svc.RevokeAllSessions(r.Context(), user, except); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "sessions revoked"}, nil)
}

// FormSessionsList lists the current session user's active sessions.
func (h *Handler) FormSessionsList(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	sessions, err := h.svc.Sessions(r.Context(), user.ID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, sessions, nil)
}

// FormSessionRevoke revokes one of the current session user's active sessions.
func (h *Handler) FormSessionRevoke(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.RevokeSession(r.Context(), user, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "session revoked"}, nil)
}

// FormSessionsRevokeAll revokes all of the current session user's active
// sessions except the one named by the "except" query parameter, if any.
func (h *Handler) FormSessionsRevokeAll(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	except := r.URL.Query().Get("except")
	if err := h.svc.RevokeAllSessions(r.Context(), user, except); err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "sessions revoked"}, nil)
}
