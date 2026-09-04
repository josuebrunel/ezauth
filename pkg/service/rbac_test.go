package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func TestRBAC(t *testing.T) {
	auth := setupTestDB(t)
	auth.Cfg.AuditLog.Enabled = true
	ctx := context.Background()

	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("rbac"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	t.Run("RoleCreate_Duplicate", func(t *testing.T) {
		if _, err := auth.RoleCreate(ctx, "editor", "can edit content"); err != nil {
			t.Fatalf("RoleCreate() unexpected error: %v", err)
		}
		if _, err := auth.RoleCreate(ctx, "editor", "duplicate"); err == nil {
			t.Error("expected error creating a duplicate role, got nil")
		}
	})

	t.Run("PermissionCreate_Duplicate", func(t *testing.T) {
		if _, err := auth.PermissionCreate(ctx, "posts:write", "write posts"); err != nil {
			t.Fatalf("PermissionCreate() unexpected error: %v", err)
		}
		if _, err := auth.PermissionCreate(ctx, "posts:write", "duplicate"); err == nil {
			t.Error("expected error creating a duplicate permission, got nil")
		}
	})

	t.Run("UserRoleGrant_IdempotentAndHasRole", func(t *testing.T) {
		has, err := auth.UserHasRole(ctx, user.ID, "editor")
		if err != nil {
			t.Fatalf("UserHasRole() unexpected error: %v", err)
		}
		if has {
			t.Error("expected user not to have role before granting")
		}

		if err := auth.UserRoleGrant(ctx, user.ID, "editor"); err != nil {
			t.Fatalf("UserRoleGrant() unexpected error: %v", err)
		}
		// Granting again must be a no-op, not an error (idempotent) — and must
		// not fire a second audit event, since it's a DB-level no-op (RowsAffected
		// == 0), not a fresh grant.
		if err := auth.UserRoleGrant(ctx, user.ID, "editor"); err != nil {
			t.Fatalf("UserRoleGrant() (repeat) unexpected error: %v", err)
		}

		auditResult, err := auth.AuditLogs(ctx, user.ID, ListAuditLogsOptions{EventType: models.AuditEventRoleGranted})
		if err != nil {
			t.Fatalf("AuditLogs() unexpected error: %v", err)
		}
		if len(auditResult.Events) != 1 {
			t.Errorf("expected exactly 1 role.granted audit event after granting the same role twice, got %d", len(auditResult.Events))
		}

		has, err = auth.UserHasRole(ctx, user.ID, "editor")
		if err != nil {
			t.Fatalf("UserHasRole() unexpected error: %v", err)
		}
		if !has {
			t.Error("expected user to have role after granting")
		}

		roles, err := auth.UserRolesList(ctx, user.ID)
		if err != nil {
			t.Fatalf("UserRolesList() unexpected error: %v", err)
		}
		if len(roles) != 1 || roles[0].Name != "editor" {
			t.Errorf("expected exactly one role 'editor', got %+v", roles)
		}
	})

	t.Run("RolePermissionGrant_And_UserHasPermission", func(t *testing.T) {
		has, err := auth.UserHasPermission(ctx, user.ID, "posts:write")
		if err != nil {
			t.Fatalf("UserHasPermission() unexpected error: %v", err)
		}
		if has {
			t.Error("expected user not to have permission before granting to role")
		}

		if err := auth.RolePermissionGrant(ctx, "editor", "posts:write"); err != nil {
			t.Fatalf("RolePermissionGrant() unexpected error: %v", err)
		}
		// Granting again must be a no-op, not an error (idempotent).
		if err := auth.RolePermissionGrant(ctx, "editor", "posts:write"); err != nil {
			t.Fatalf("RolePermissionGrant() (repeat) unexpected error: %v", err)
		}

		has, err = auth.UserHasPermission(ctx, user.ID, "posts:write")
		if err != nil {
			t.Fatalf("UserHasPermission() unexpected error: %v", err)
		}
		if !has {
			t.Error("expected user to have permission transitively via their role")
		}
	})

	t.Run("RolePermissionRevoke", func(t *testing.T) {
		if err := auth.RolePermissionRevoke(ctx, "editor", "posts:write"); err != nil {
			t.Fatalf("RolePermissionRevoke() unexpected error: %v", err)
		}
		has, err := auth.UserHasPermission(ctx, user.ID, "posts:write")
		if err != nil {
			t.Fatalf("UserHasPermission() unexpected error: %v", err)
		}
		if has {
			t.Error("expected user not to have permission after revoking it from their role")
		}
	})

	t.Run("UserRoleRevoke_IdempotentAndHasRole", func(t *testing.T) {
		if err := auth.UserRoleRevoke(ctx, user.ID, "editor"); err != nil {
			t.Fatalf("UserRoleRevoke() unexpected error: %v", err)
		}
		// Revoking again must be a no-op, not an error (idempotent).
		if err := auth.UserRoleRevoke(ctx, user.ID, "editor"); err != nil {
			t.Fatalf("UserRoleRevoke() (repeat) unexpected error: %v", err)
		}

		has, err := auth.UserHasRole(ctx, user.ID, "editor")
		if err != nil {
			t.Fatalf("UserHasRole() unexpected error: %v", err)
		}
		if has {
			t.Error("expected user not to have role after revoking")
		}
	})

	t.Run("RoleDelete_CascadesAssignments", func(t *testing.T) {
		role, err := auth.RoleCreate(ctx, "temp-role", "")
		if err != nil {
			t.Fatalf("RoleCreate() unexpected error: %v", err)
		}
		permission, err := auth.PermissionCreate(ctx, "temp:perm", "")
		if err != nil {
			t.Fatalf("PermissionCreate() unexpected error: %v", err)
		}
		if err := auth.UserRoleGrant(ctx, user.ID, "temp-role"); err != nil {
			t.Fatalf("UserRoleGrant() unexpected error: %v", err)
		}
		if err := auth.RolePermissionGrant(ctx, "temp-role", "temp:perm"); err != nil {
			t.Fatalf("RolePermissionGrant() unexpected error: %v", err)
		}

		if err := auth.RoleDelete(ctx, role.ID); err != nil {
			t.Fatalf("RoleDelete() unexpected error: %v", err)
		}

		has, err := auth.UserHasRole(ctx, user.ID, "temp-role")
		if err != nil {
			t.Fatalf("UserHasRole() unexpected error: %v", err)
		}
		if has {
			t.Error("expected the user_roles assignment to be cascade-deleted with the role")
		}

		remainingPermissions, err := auth.Repo.PermissionsByRoleID(ctx, role.ID)
		if err != nil {
			t.Fatalf("PermissionsByRoleID() unexpected error: %v", err)
		}
		if len(remainingPermissions) != 0 {
			t.Errorf("expected the role_permissions assignment to be cascade-deleted with the role, got %+v", remainingPermissions)
		}

		if err := auth.PermissionDelete(ctx, permission.ID); err != nil {
			t.Fatalf("PermissionDelete() unexpected error: %v", err)
		}
	})
}
