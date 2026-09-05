package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/josuebrunel/ezauth/pkg/service"
)

// createOrganizationRequest is the request body for OrganizationCreate.
type createOrganizationRequest struct {
	Name string `json:"name"`
}

// addOrgMemberRequest is the request body for OrgMemberAdd.
type addOrgMemberRequest struct {
	UserID   string `json:"user_id"`
	RoleName string `json:"role_name"`
}

// parseOrganizationsListOptions builds service.ListOrganizationsOptions
// from the shared limit/offset query params.
func parseOrganizationsListOptions(r *http.Request) service.ListOrganizationsOptions {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	return service.ListOrganizationsOptions{Limit: limit, Offset: offset}
}

// OrganizationCreate creates a new organization.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Create an organization (admin)
// @Tags organizations
// @Accept json
// @Produce json
// @Param request body createOrganizationRequest true "Organization name"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.Organization]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/organizations [post]
func (h *Handler) OrganizationCreate(w http.ResponseWriter, r *http.Request) {
	var req createOrganizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	org, err := h.svc.OrganizationCreate(r.Context(), req.Name)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, org, nil)
}

// FormOrganizationCreate creates a new organization for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormOrganizationCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	org, err := h.svc.OrganizationCreate(r.Context(), r.FormValue("name"))
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, org, nil)
}

// OrganizationsList lists organizations, paginated.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary List organizations (admin)
// @Tags organizations
// @Produce json
// @Param limit query int false "Page size (default 50, max 200)"
// @Param offset query int false "Page offset"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.ListOrganizationsResult]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/organizations [get]
func (h *Handler) OrganizationsList(w http.ResponseWriter, r *http.Request) {
	result, err := h.svc.OrganizationsList(r.Context(), parseOrganizationsListOptions(r))
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, result, nil)
}

// FormOrganizationsList lists organizations for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormOrganizationsList(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	result, err := h.svc.OrganizationsList(r.Context(), parseOrganizationsListOptions(r))
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, result, nil)
}

// OrganizationGetByID retrieves an organization by its ID.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Get an organization (admin)
// @Tags organizations
// @Produce json
// @Param id path string true "Organization ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.Organization]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/organizations/{id} [get]
func (h *Handler) OrganizationGetByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	org, err := h.svc.OrganizationGetByID(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, org, nil)
}

// FormOrganizationGetByID retrieves an organization by its ID for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormOrganizationGetByID(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	org, err := h.svc.OrganizationGetByID(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, org, nil)
}

// OrganizationDelete deletes an organization. Matching org_members rows
// are removed via ON DELETE CASCADE.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Delete an organization (admin)
// @Tags organizations
// @Produce json
// @Param id path string true "Organization ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/organizations/{id} [delete]
func (h *Handler) OrganizationDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.OrganizationDelete(r.Context(), id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "organization deleted", nil)
}

// FormOrganizationDelete deletes an organization for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormOrganizationDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.OrganizationDelete(r.Context(), id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "organization deleted", nil)
}

// OrgMemberAdd grants a user a role within an organization. Updates the
// role if the user is already a member.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Add/update an organization member (admin)
// @Tags organizations
// @Accept json
// @Produce json
// @Param id path string true "Organization ID"
// @Param request body addOrgMemberRequest true "User ID and role name"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/organizations/{id}/members [post]
func (h *Handler) OrgMemberAdd(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req addOrgMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.OrgMemberAdd(r.Context(), id, req.UserID, req.RoleName); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "member added", nil)
}

// FormOrgMemberAdd adds an organization member for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormOrgMemberAdd(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.OrgMemberAdd(r.Context(), id, r.FormValue("user_id"), r.FormValue("role_name")); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "member added", nil)
}

// OrgMembersList lists an organization's members, with each member's role
// name joined in.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary List an organization's members (admin)
// @Tags organizations
// @Produce json
// @Param id path string true "Organization ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]models.OrgMember]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/organizations/{id}/members [get]
func (h *Handler) OrgMembersList(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	members, err := h.svc.OrgMembersList(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, members, nil)
}

// FormOrgMembersList lists an organization's members for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormOrgMembersList(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	members, err := h.svc.OrgMembersList(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, members, nil)
}

// OrgMemberRemove removes a user's membership from an organization.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Remove an organization member (admin)
// @Tags organizations
// @Produce json
// @Param id path string true "Organization ID"
// @Param user_id path string true "User ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/organizations/{id}/members/{user_id} [delete]
func (h *Handler) OrgMemberRemove(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "user_id")
	if err := h.svc.OrgMemberRemove(r.Context(), id, userID); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "member removed", nil)
}

// FormOrgMemberRemove removes an organization member for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormOrgMemberRemove(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "user_id")
	if err := h.svc.OrgMemberRemove(r.Context(), id, userID); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "member removed", nil)
}

// UserOrganizationsList lists the organizations a user belongs to.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary List a user's organizations (admin)
// @Tags organizations
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]models.Organization]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/users/{id}/organizations [get]
func (h *Handler) UserOrganizationsList(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	orgs, err := h.svc.UserOrganizationsList(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, orgs, nil)
}

// FormUserOrganizationsList lists the organizations a user belongs to for
// the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormUserOrganizationsList(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	orgs, err := h.svc.UserOrganizationsList(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, orgs, nil)
}
