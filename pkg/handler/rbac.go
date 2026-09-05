package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// nameDescriptionRequest is the shared request body shape for creating a
// role or permission — both are just a unique name plus an optional
// human-readable description.
type nameDescriptionRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// grantRoleRequest is the request body for UserRoleGrant.
type grantRoleRequest struct {
	RoleName string `json:"role_name"`
}

// grantPermissionRequest is the request body for RolePermissionGrant.
type grantPermissionRequest struct {
	PermissionName string `json:"permission_name"`
}

// RoleCreate creates a new RBAC role.
//
// ezauth performs no authorization check here — the caller is responsible
// for verifying the requester is allowed (e.g. via an admin-only middleware
// checking RequireRole/RequirePermission) before this route is reachable.
// @Summary Create a role (admin)
// @Tags rbac
// @Accept json
// @Produce json
// @Param request body nameDescriptionRequest true "Role name and description"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.Role]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/roles [post]
func (h *Handler) RoleCreate(w http.ResponseWriter, r *http.Request) {
	var req nameDescriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	role, err := h.svc.RoleCreate(r.Context(), req.Name, req.Description)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, role, nil)
}

// FormRoleCreate creates a new RBAC role for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormRoleCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	role, err := h.svc.RoleCreate(r.Context(), r.FormValue("name"), r.FormValue("description"))
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, role, nil)
}

// RolesList lists all RBAC roles.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary List roles (admin)
// @Tags rbac
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]models.Role]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/roles [get]
func (h *Handler) RolesList(w http.ResponseWriter, r *http.Request) {
	roles, err := h.svc.RolesList(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, roles, nil)
}

// FormRolesList lists all RBAC roles for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormRolesList(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	roles, err := h.svc.RolesList(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, roles, nil)
}

// RoleDelete deletes a role. Matching user/role and role/permission
// assignments are removed via ON DELETE CASCADE.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Delete a role (admin)
// @Tags rbac
// @Produce json
// @Param id path string true "Role ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/roles/{id} [delete]
func (h *Handler) RoleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.RoleDelete(r.Context(), id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "role deleted", nil)
}

// FormRoleDelete deletes a role for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormRoleDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.RoleDelete(r.Context(), id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "role deleted", nil)
}

// PermissionCreate creates a new RBAC permission.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Create a permission (admin)
// @Tags rbac
// @Accept json
// @Produce json
// @Param request body nameDescriptionRequest true "Permission name and description"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.Permission]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/permissions [post]
func (h *Handler) PermissionCreate(w http.ResponseWriter, r *http.Request) {
	var req nameDescriptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	permission, err := h.svc.PermissionCreate(r.Context(), req.Name, req.Description)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, permission, nil)
}

// FormPermissionCreate creates a new RBAC permission for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormPermissionCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	permission, err := h.svc.PermissionCreate(r.Context(), r.FormValue("name"), r.FormValue("description"))
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, permission, nil)
}

// PermissionsList lists all RBAC permissions.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary List permissions (admin)
// @Tags rbac
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]models.Permission]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/permissions [get]
func (h *Handler) PermissionsList(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.svc.PermissionsList(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, permissions, nil)
}

// FormPermissionsList lists all RBAC permissions for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormPermissionsList(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	permissions, err := h.svc.PermissionsList(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, permissions, nil)
}

// PermissionDelete deletes a permission. Matching role/permission
// assignments are removed via ON DELETE CASCADE.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Delete a permission (admin)
// @Tags rbac
// @Produce json
// @Param id path string true "Permission ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/permissions/{id} [delete]
func (h *Handler) PermissionDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.svc.PermissionDelete(r.Context(), id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "permission deleted", nil)
}

// FormPermissionDelete deletes a permission for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormPermissionDelete(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.PermissionDelete(r.Context(), id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "permission deleted", nil)
}

// UserRoleGrant grants a role to a user by role name. Idempotent, and
// records an audit event (models.AuditEventRoleGranted).
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Grant a role to a user (admin)
// @Tags rbac
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body grantRoleRequest true "Role name"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/users/{id}/roles [post]
func (h *Handler) UserRoleGrant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req grantRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.UserRoleGrant(r.Context(), id, req.RoleName); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "role granted", nil)
}

// FormUserRoleGrant grants a role to a user for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormUserRoleGrant(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	id := chi.URLParam(r, "id")
	if err := h.svc.UserRoleGrant(r.Context(), id, r.FormValue("role_name")); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "role granted", nil)
}

// UserRolesList lists the roles granted to a user.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary List a user's roles (admin)
// @Tags rbac
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]models.Role]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/admin/users/{id}/roles [get]
func (h *Handler) UserRolesList(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	roles, err := h.svc.UserRolesList(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, roles, nil)
}

// FormUserRolesList lists the roles granted to a user for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormUserRolesList(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	roles, err := h.svc.UserRolesList(r.Context(), id)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, roles, nil)
}

// UserRoleRevoke revokes a role from a user by role name. Idempotent, and
// records an audit event (models.AuditEventRoleRevoked).
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Revoke a role from a user (admin)
// @Tags rbac
// @Produce json
// @Param id path string true "User ID"
// @Param role_name path string true "Role name"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/users/{id}/roles/{role_name} [delete]
func (h *Handler) UserRoleRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	roleName := chi.URLParam(r, "role_name")
	if err := h.svc.UserRoleRevoke(r.Context(), id, roleName); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "role revoked", nil)
}

// FormUserRoleRevoke revokes a role from a user for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormUserRoleRevoke(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	roleName := chi.URLParam(r, "role_name")
	if err := h.svc.UserRoleRevoke(r.Context(), id, roleName); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "role revoked", nil)
}

// RolePermissionGrant grants a permission to a role, both identified by name.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Grant a permission to a role (admin)
// @Tags rbac
// @Accept json
// @Produce json
// @Param name path string true "Role name"
// @Param request body grantPermissionRequest true "Permission name"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/roles/{name}/permissions [post]
func (h *Handler) RolePermissionGrant(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req grantPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if err := h.svc.RolePermissionGrant(r.Context(), name, req.PermissionName); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "permission granted", nil)
}

// FormRolePermissionGrant grants a permission to a role for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormRolePermissionGrant(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	name := chi.URLParam(r, "name")
	if err := h.svc.RolePermissionGrant(r.Context(), name, r.FormValue("permission_name")); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "permission granted", nil)
}

// RolePermissionRevoke revokes a permission from a role, both identified by name.
//
// ezauth performs no authorization check here — see RoleCreate.
// @Summary Revoke a permission from a role (admin)
// @Tags rbac
// @Produce json
// @Param name path string true "Role name"
// @Param permission_name path string true "Permission name"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/admin/roles/{name}/permissions/{permission_name} [delete]
func (h *Handler) RolePermissionRevoke(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	permissionName := chi.URLParam(r, "permission_name")
	if err := h.svc.RolePermissionRevoke(r.Context(), name, permissionName); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "permission revoked", nil)
}

// FormRolePermissionRevoke revokes a permission from a role for the current session user.
// ezauth performs no authorization check here — see RoleCreate.
func (h *Handler) FormRolePermissionRevoke(w http.ResponseWriter, r *http.Request) {
	if _, err := h.GetSessionUser(r.Context()); err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	name := chi.URLParam(r, "name")
	permissionName := chi.URLParam(r, "permission_name")
	if err := h.svc.RolePermissionRevoke(r.Context(), name, permissionName); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, "permission revoked", nil)
}
