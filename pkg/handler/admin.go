package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/josuebrunel/ezauth/pkg/service"
)

// parseListUsersOptions builds ListUsersOptions from query params shared by
// the JSON API and form variants of AdminUsersList:
//
//	search, status, limit, offset, created_after, created_before,
//	last_active_after, last_active_before (all optional; the four *_after/
//	*_before params are RFC3339 timestamps).
func parseListUsersOptions(r *http.Request) (service.ListUsersOptions, error) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	opts := service.ListUsersOptions{
		Search: q.Get("search"),
		Status: q.Get("status"),
		Limit:  limit,
		Offset: offset,
	}

	for param, dst := range map[string]**time.Time{
		"created_after":      &opts.CreatedAfter,
		"created_before":     &opts.CreatedBefore,
		"last_active_after":  &opts.LastActiveAfter,
		"last_active_before": &opts.LastActiveBefore,
	} {
		v := q.Get(param)
		if v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return opts, ErrInvalidTimestampFilter
		}
		*dst = &t
	}

	return opts, nil
}

// AdminUsersList lists/searches/filters users.
//
// ezauth performs no authorization check here — same stance as Impersonate.
// The caller is responsible for verifying the requester is allowed to list
// users (e.g. via an admin-only middleware checking caller.HasRole("admin"))
// before this route is reachable.
// @Summary List/search users (admin)
// @Tags admin
// @Produce json
// @Param search query string false "Filter by email/username substring"
// @Param status query string false "Filter by status: active, locked, or suspended"
// @Param created_after query string false "RFC3339 timestamp"
// @Param created_before query string false "RFC3339 timestamp"
// @Param last_active_after query string false "RFC3339 timestamp"
// @Param last_active_before query string false "RFC3339 timestamp"
// @Param limit query int false "Page size (default 20, max 100)"
// @Param offset query int false "Page offset"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.ListUsersResult]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/users [get]
func (h *Handler) AdminUsersList(w http.ResponseWriter, r *http.Request) {
	opts, err := parseListUsersOptions(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	result, err := h.svc.UsersList(r.Context(), opts)
	if err != nil {
		status := http.StatusInternalServerError
		if err == service.ErrInvalidUserStatusFilter {
			status = http.StatusBadRequest
		}
		WriteJSONResponseError(w, status, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, result, nil)
}

// AdminUserSuspend deactivates a user's account.
//
// ezauth performs no authorization check here — see AdminUsersList.
// @Summary Suspend a user (admin)
// @Tags admin
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.User]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/users/{id}/suspend [post]
func (h *Handler) AdminUserSuspend(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.svc.UserSuspend(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	user.Sanitize()
	WriteJSONResponse(w, http.StatusOK, user, nil)
}

// AdminUserReactivate re-enables a suspended or locked-out user's account.
//
// ezauth performs no authorization check here — see AdminUsersList.
// @Summary Reactivate a user (admin)
// @Tags admin
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.User]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/users/{id}/reactivate [post]
func (h *Handler) AdminUserReactivate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.svc.UserReactivate(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	user.Sanitize()
	WriteJSONResponse(w, http.StatusOK, user, nil)
}

// AdminUserAuthHistory returns a user's recent authentication-related token history.
//
// ezauth performs no authorization check here — see AdminUsersList.
// @Summary View a user's auth history (admin)
// @Tags admin
// @Produce json
// @Param id path string true "User ID"
// @Param limit query int false "Max entries (default 50, max 200)"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]service.AuthHistoryEntry]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/users/{id}/history [get]
func (h *Handler) AdminUserAuthHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	history, err := h.svc.UserAuthHistory(r.Context(), id, limit)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, history, nil)
}

// FormAdminUsersList lists/searches users for the current session user.
// ezauth performs no authorization check here — see AdminUsersList.
func (h *Handler) FormAdminUsersList(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	opts, err := parseListUsersOptions(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	result, err := h.svc.UsersList(r.Context(), opts)
	if err != nil {
		status := http.StatusInternalServerError
		if err == service.ErrInvalidUserStatusFilter {
			status = http.StatusBadRequest
		}
		WriteJSONResponseError(w, status, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, result, nil)
}

// FormAdminUserSuspend deactivates a user's account for the current session user.
// ezauth performs no authorization check here — see AdminUsersList.
func (h *Handler) FormAdminUserSuspend(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	user, err := h.svc.UserSuspend(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	user.Sanitize()
	WriteJSONResponse(w, http.StatusOK, user, nil)
}

// FormAdminUserReactivate re-enables a user's account for the current session user.
// ezauth performs no authorization check here — see AdminUsersList.
func (h *Handler) FormAdminUserReactivate(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	user, err := h.svc.UserReactivate(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	user.Sanitize()
	WriteJSONResponse(w, http.StatusOK, user, nil)
}

// FormAdminUserAuthHistory returns a user's auth history for the current session user.
// ezauth performs no authorization check here — see AdminUsersList.
func (h *Handler) FormAdminUserAuthHistory(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	history, err := h.svc.UserAuthHistory(r.Context(), id, limit)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, history, nil)
}
