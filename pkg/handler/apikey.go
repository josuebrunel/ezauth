package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// createAPIKeyRequest is the request body for APIKeyCreate.
type createAPIKeyRequest struct {
	Scopes []string `json:"scopes"`
}

// APIKeyCreate creates a new API key for the authenticated user, optionally
// scoped to a limited set of actions (enforced via RequireAPIKeyScope). An
// empty/omitted scopes list grants the same access as the full account.
//
// The raw key value is only ever returned here — it cannot be recovered
// later, only revoked.
// @Summary Create an API key
// @Tags api-keys
// @Accept json
// @Produce json
// @Param request body createAPIKeyRequest true "Optional scopes"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.Token]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/api-keys [post]
func (h *Handler) APIKeyCreate(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}

	var req createAPIKeyRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
			return
		}
	}

	key, err := h.svc.APIKeyCreate(r.Context(), userID, req.Scopes)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, key, nil)
}

// FormAPIKeyCreate creates a new API key for the current session user.
func (h *Handler) FormAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	// Repeat the "scopes" field to request more than one, e.g.
	// scopes=posts:write&scopes=posts:read. Omit it entirely for an
	// unscoped, full-access key.
	key, err := h.svc.APIKeyCreate(r.Context(), user.ID, r.Form["scopes"])
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, key, nil)
}

// APIKeysList lists the authenticated user's API keys.
// @Summary List API keys
// @Tags api-keys
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]service.APIKeyInfo]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/api-keys [get]
func (h *Handler) APIKeysList(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}

	keys, err := h.svc.APIKeysList(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, keys, nil)
}

// FormAPIKeysList lists the current session user's API keys.
func (h *Handler) FormAPIKeysList(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	keys, err := h.svc.APIKeysList(r.Context(), user.ID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, keys, nil)
}

// APIKeyRevoke revokes one of the authenticated user's API keys. Revoking
// a key ID that doesn't exist or belongs to another user fails the same
// way (ErrAPIKeyNotFound) so the endpoint can't be used to probe for
// other users' key IDs.
// @Summary Revoke an API key
// @Tags api-keys
// @Produce json
// @Param id path string true "API key (token) ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/api-keys/{id} [delete]
func (h *Handler) APIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.APIKeyRevoke(r.Context(), userID, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "api key revoked", nil)
}

// FormAPIKeyRevoke revokes one of the current session user's API keys.
func (h *Handler) FormAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.APIKeyRevoke(r.Context(), user.ID, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "api key revoked", nil)
}
