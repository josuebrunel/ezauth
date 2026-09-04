package service

import (
	"context"
	"errors"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

// RoleCreate creates a new RBAC role. Real RBAC (roles/permissions tables +
// RequireRole/RequirePermission middleware) is a fully separate, additive
// system from the legacy comma-separated User.Roles/HasRole/AddRole helpers
// on models.User — those keep working unchanged, but RequireRole/
// RequirePermission consult these tables, not that field.
func (a *Auth) RoleCreate(ctx context.Context, name, description string) (*models.Role, error) {
	if name == "" {
		return nil, errors.New("role name is required")
	}
	if _, err := a.Repo.RoleGetByName(ctx, name); err == nil {
		return nil, errors.New("role already exists")
	}
	role, err := a.Repo.RoleCreate(ctx, &models.Role{Name: name, Description: description})
	if err != nil {
		xlog.Error("failed to create role", "name", name, "err", err)
		return nil, err
	}
	return role, nil
}

// RolesList lists all RBAC roles.
func (a *Auth) RolesList(ctx context.Context) ([]*models.Role, error) {
	return a.Repo.RolesList(ctx)
}

// RoleDelete deletes a role. Matching user/role and role/permission
// assignments are removed via ON DELETE CASCADE.
func (a *Auth) RoleDelete(ctx context.Context, id string) error {
	return a.Repo.RoleDelete(ctx, id)
}

// PermissionCreate creates a new RBAC permission.
func (a *Auth) PermissionCreate(ctx context.Context, name, description string) (*models.Permission, error) {
	if name == "" {
		return nil, errors.New("permission name is required")
	}
	if _, err := a.Repo.PermissionGetByName(ctx, name); err == nil {
		return nil, errors.New("permission already exists")
	}
	permission, err := a.Repo.PermissionCreate(ctx, &models.Permission{Name: name, Description: description})
	if err != nil {
		xlog.Error("failed to create permission", "name", name, "err", err)
		return nil, err
	}
	return permission, nil
}

// PermissionsList lists all RBAC permissions.
func (a *Auth) PermissionsList(ctx context.Context) ([]*models.Permission, error) {
	return a.Repo.PermissionsList(ctx)
}

// PermissionDelete deletes a permission. Matching role/permission
// assignments are removed via ON DELETE CASCADE.
func (a *Auth) PermissionDelete(ctx context.Context, id string) error {
	return a.Repo.PermissionDelete(ctx, id)
}

// UserRoleGrant grants a role to a user by role name, and records an audit
// event. Idempotent at the DB level (see Repo.UserRoleGrant): granting a
// role the user already holds is a no-op, no audit event fired.
func (a *Auth) UserRoleGrant(ctx context.Context, userID, roleName string) error {
	role, err := a.Repo.RoleGetByName(ctx, roleName)
	if err != nil {
		xlog.Debug("grant role failed: role not found", "role", roleName, "err", err)
		return errors.New("role not found")
	}
	granted, err := a.Repo.UserRoleGrant(ctx, userID, role.ID)
	if err != nil {
		xlog.Error("failed to grant role", "user_id", userID, "role", roleName, "err", err)
		return err
	}
	if !granted {
		return nil
	}
	a.recordAuditEvent(ctx, userID, models.AuditEventRoleGranted, models.JSONMap{"role": roleName})
	xlog.Info("role granted", "user_id", userID, "role", roleName)
	return nil
}

// UserRoleRevoke revokes a role from a user by role name, and records an
// audit event. Idempotent: revoking a role the user doesn't hold is a
// no-op, no audit event fired.
func (a *Auth) UserRoleRevoke(ctx context.Context, userID, roleName string) error {
	role, err := a.Repo.RoleGetByName(ctx, roleName)
	if err != nil {
		xlog.Debug("revoke role failed: role not found", "role", roleName, "err", err)
		return errors.New("role not found")
	}
	revoked, err := a.Repo.UserRoleRevoke(ctx, userID, role.ID)
	if err != nil {
		xlog.Error("failed to revoke role", "user_id", userID, "role", roleName, "err", err)
		return err
	}
	if !revoked {
		return nil
	}
	a.recordAuditEvent(ctx, userID, models.AuditEventRoleRevoked, models.JSONMap{"role": roleName})
	xlog.Info("role revoked", "user_id", userID, "role", roleName)
	return nil
}

// RolePermissionGrant grants a permission to a role, both identified by
// name. Idempotent at the DB level (see Repo.RolePermissionGrant).
func (a *Auth) RolePermissionGrant(ctx context.Context, roleName, permissionName string) error {
	role, err := a.Repo.RoleGetByName(ctx, roleName)
	if err != nil {
		return errors.New("role not found")
	}
	permission, err := a.Repo.PermissionGetByName(ctx, permissionName)
	if err != nil {
		return errors.New("permission not found")
	}
	if _, err := a.Repo.RolePermissionGrant(ctx, role.ID, permission.ID); err != nil {
		xlog.Error("failed to grant permission to role", "role", roleName, "permission", permissionName, "err", err)
		return err
	}
	xlog.Info("permission granted to role", "role", roleName, "permission", permissionName)
	return nil
}

// RolePermissionRevoke revokes a permission from a role, both identified by name.
func (a *Auth) RolePermissionRevoke(ctx context.Context, roleName, permissionName string) error {
	role, err := a.Repo.RoleGetByName(ctx, roleName)
	if err != nil {
		return errors.New("role not found")
	}
	permission, err := a.Repo.PermissionGetByName(ctx, permissionName)
	if err != nil {
		return errors.New("permission not found")
	}
	if err := a.Repo.RolePermissionRevoke(ctx, role.ID, permission.ID); err != nil {
		xlog.Error("failed to revoke permission from role", "role", roleName, "permission", permissionName, "err", err)
		return err
	}
	xlog.Info("permission revoked from role", "role", roleName, "permission", permissionName)
	return nil
}

// UserRolesList lists the roles granted to a user.
func (a *Auth) UserRolesList(ctx context.Context, userID string) ([]*models.Role, error) {
	return a.Repo.RolesByUserID(ctx, userID)
}

// UserHasRole reports whether the user holds the given role, checked against
// the RBAC tables (not the legacy User.Roles string field).
func (a *Auth) UserHasRole(ctx context.Context, userID, roleName string) (bool, error) {
	roles, err := a.Repo.RolesByUserID(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Name == roleName {
			return true, nil
		}
	}
	return false, nil
}

// UserHasPermission reports whether the user holds the given permission,
// resolved transitively through every role granted to them.
func (a *Auth) UserHasPermission(ctx context.Context, userID, permissionName string) (bool, error) {
	permissions, err := a.Repo.PermissionsByUserID(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, p := range permissions {
		if p.Name == permissionName {
			return true, nil
		}
	}
	return false, nil
}
