package service

import (
	"context"
	"errors"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

// OrganizationCreate creates a new organization.
func (a *Auth) OrganizationCreate(ctx context.Context, name string) (*models.Organization, error) {
	if name == "" {
		return nil, errors.New("organization name is required")
	}
	org, err := a.Repo.OrganizationCreate(ctx, &models.Organization{Name: name})
	if err != nil {
		xlog.Error("failed to create organization", "name", name, "err", err)
		return nil, err
	}
	return org, nil
}

// OrganizationGetByID retrieves an organization by its ID — typically used
// inside an OrgLoader (see OrgLoaderMiddleware) to resolve the "current org".
func (a *Auth) OrganizationGetByID(ctx context.Context, id string) (*models.Organization, error) {
	return a.Repo.OrganizationGetByID(ctx, id)
}

// OrganizationsList lists all organizations.
func (a *Auth) OrganizationsList(ctx context.Context) ([]*models.Organization, error) {
	return a.Repo.OrganizationsList(ctx)
}

// OrganizationDelete deletes an organization. Matching org_members rows
// are removed via ON DELETE CASCADE.
func (a *Auth) OrganizationDelete(ctx context.Context, id string) error {
	return a.Repo.OrganizationDelete(ctx, id)
}

// OrgMemberAdd grants userID the given role within orgID, drawn from the
// same role catalog RequireRole/RequirePermission check (see #114). If the
// user is already a member, their role is updated instead.
func (a *Auth) OrgMemberAdd(ctx context.Context, orgID, userID, roleName string) error {
	role, err := a.Repo.RoleGetByName(ctx, roleName)
	if err != nil {
		xlog.Debug("add org member failed: role not found", "role", roleName, "err", err)
		return errors.New("role not found")
	}
	if err := a.Repo.OrgMemberUpsert(ctx, orgID, userID, role.ID); err != nil {
		xlog.Error("failed to add org member", "org_id", orgID, "user_id", userID, "role", roleName, "err", err)
		return err
	}
	xlog.Info("org member added", "org_id", orgID, "user_id", userID, "role", roleName)
	return nil
}

// OrgMemberRemove removes a user's membership from an organization.
func (a *Auth) OrgMemberRemove(ctx context.Context, orgID, userID string) error {
	if err := a.Repo.OrgMemberRemove(ctx, orgID, userID); err != nil {
		xlog.Error("failed to remove org member", "org_id", orgID, "user_id", userID, "err", err)
		return err
	}
	xlog.Info("org member removed", "org_id", orgID, "user_id", userID)
	return nil
}

// OrgMembersList lists an organization's members, with each member's role name joined in.
func (a *Auth) OrgMembersList(ctx context.Context, orgID string) ([]*models.OrgMember, error) {
	return a.Repo.OrgMembersByOrgID(ctx, orgID)
}

// UserOrganizationsList lists the organizations a user belongs to.
func (a *Auth) UserOrganizationsList(ctx context.Context, userID string) ([]*models.Organization, error) {
	return a.Repo.OrganizationsByUserID(ctx, userID)
}
