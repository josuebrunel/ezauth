package service

import (
	"context"
	"errors"
	"strings"

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

const (
	defaultOrganizationsListLimit = 50
	maxOrganizationsListLimit     = 200
)

// ListOrganizationsOptions defines the pagination parameters for
// OrganizationsList. Zero-valued Limit defaults to 50; Limit is capped at 200.
type ListOrganizationsOptions struct {
	Limit  int
	Offset int
}

// ListOrganizationsResult is the paginated result of OrganizationsList.
type ListOrganizationsResult struct {
	Organizations []*models.Organization `json:"organizations"`
	HasMore       bool                   `json:"has_more"`
}

// OrganizationsList lists organizations, name-ordered. Real multi-tenant
// deployments can have many organizations (unlike the RBAC roles/permissions
// catalogs, which are small and admin-curated, so RolesList/PermissionsList
// stay unpaginated), so this is paginated like UsersList/AuditLogs.
func (a *Auth) OrganizationsList(ctx context.Context, opts ListOrganizationsOptions) (*ListOrganizationsResult, error) {
	limit := opts.Limit
	if limit <= 0 || limit > maxOrganizationsListLimit {
		limit = defaultOrganizationsListLimit
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	orgs, hasMore, err := a.Repo.OrganizationsList(ctx, limit, offset)
	if err != nil {
		return nil, err
	}
	return &ListOrganizationsResult{Organizations: orgs, HasMore: hasMore}, nil
}

// OrganizationDelete deletes an organization. Matching org_members rows
// are removed via ON DELETE CASCADE.
func (a *Auth) OrganizationDelete(ctx context.Context, id string) error {
	return a.Repo.OrganizationDelete(ctx, id)
}

// ErrOrgMemberCannotHoldAdminRole is returned by OrgMemberAdd when roleName
// is the configured global AdminRole: org-scoped membership grants must not
// be usable to escalate to application-wide admin, which RequireRole checks
// for on every admin-gated route regardless of which organization (if any)
// the caller belongs to.
var ErrOrgMemberCannotHoldAdminRole = errors.New("cannot grant the global admin role through organization membership")

// OrgMemberAdd grants userID the given role within orgID, drawn from the
// same role catalog RequireRole/RequirePermission check (see #114) -- except
// Cfg.AdminRole itself, which OrgMemberAdd always refuses (see
// ErrOrgMemberCannotHoldAdminRole). If the user is already a member, their
// role is updated instead.
func (a *Auth) OrgMemberAdd(ctx context.Context, orgID, userID, roleName string) error {
	role, err := a.Repo.RoleGetByName(ctx, roleName)
	if err != nil {
		xlog.Debug("add org member failed: role not found", "role", roleName, "err", err)
		return errors.New("role not found")
	}
	if strings.EqualFold(role.Name, a.Cfg.AdminRole) {
		xlog.Debug("add org member refused: role is the global admin role", "org_id", orgID, "user_id", userID, "role", roleName)
		return ErrOrgMemberCannotHoldAdminRole
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

// OrgMemberRole returns the role name userID holds within orgID, and
// whether they're a member at all -- backs middleware.RequireOrgMembership/
// RequireOrgRole (see #204), which scope a route to members of the
// "current organization" (set by OrgLoaderMiddleware) instead of relying
// solely on a blanket, application-wide admin gate. isMember false with a
// nil error means "not a member", not a failure.
func (a *Auth) OrgMemberRole(ctx context.Context, orgID, userID string) (roleName string, isMember bool, err error) {
	members, err := a.Repo.OrgMembersByOrgID(ctx, orgID)
	if err != nil {
		return "", false, err
	}
	for _, m := range members {
		if m.UserID == userID {
			return m.RoleName, true, nil
		}
	}
	return "", false, nil
}

// UserOrganizationsList lists the organizations a user belongs to.
func (a *Auth) UserOrganizationsList(ctx context.Context, userID string) ([]*models.Organization, error) {
	return a.Repo.OrganizationsByUserID(ctx, userID)
}
