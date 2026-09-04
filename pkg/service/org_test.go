package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func TestOrganizations(t *testing.T) {
	auth := setupTestDB(t)
	ctx := context.Background()

	user, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:        util.UniqueEmail("org"),
		PasswordHash: "some-hash",
		Provider:     "local",
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	if _, err := auth.RoleCreate(ctx, "org-owner", "owns the organization"); err != nil {
		t.Fatalf("RoleCreate(org-owner) unexpected error: %v", err)
	}
	if _, err := auth.RoleCreate(ctx, "org-member", "regular org member"); err != nil {
		t.Fatalf("RoleCreate(org-member) unexpected error: %v", err)
	}

	var org *models.Organization

	t.Run("OrganizationCreate", func(t *testing.T) {
		var err error
		org, err = auth.OrganizationCreate(ctx, "Acme Inc")
		if err != nil {
			t.Fatalf("OrganizationCreate() unexpected error: %v", err)
		}
		if org.Name != "Acme Inc" {
			t.Errorf("expected name 'Acme Inc', got %q", org.Name)
		}
	})

	t.Run("OrganizationGetByID", func(t *testing.T) {
		got, err := auth.OrganizationGetByID(ctx, org.ID)
		if err != nil {
			t.Fatalf("OrganizationGetByID() unexpected error: %v", err)
		}
		if got.Name != "Acme Inc" {
			t.Errorf("expected name 'Acme Inc', got %q", got.Name)
		}
	})

	t.Run("OrgMemberAdd_And_List", func(t *testing.T) {
		if err := auth.OrgMemberAdd(ctx, org.ID, user.ID, "org-owner"); err != nil {
			t.Fatalf("OrgMemberAdd() unexpected error: %v", err)
		}

		members, err := auth.OrgMembersList(ctx, org.ID)
		if err != nil {
			t.Fatalf("OrgMembersList() unexpected error: %v", err)
		}
		if len(members) != 1 {
			t.Fatalf("expected 1 member, got %d", len(members))
		}
		if members[0].UserID != user.ID {
			t.Errorf("expected member user id %s, got %s", user.ID, members[0].UserID)
		}
		if members[0].RoleName != "org-owner" {
			t.Errorf("expected joined role name 'org-owner', got %q", members[0].RoleName)
		}

		orgs, err := auth.UserOrganizationsList(ctx, user.ID)
		if err != nil {
			t.Fatalf("UserOrganizationsList() unexpected error: %v", err)
		}
		if len(orgs) != 1 || orgs[0].ID != org.ID {
			t.Errorf("expected user to belong to org %s, got %+v", org.ID, orgs)
		}
	})

	t.Run("OrgMemberAdd_UpsertChangesRole", func(t *testing.T) {
		if err := auth.OrgMemberAdd(ctx, org.ID, user.ID, "org-member"); err != nil {
			t.Fatalf("OrgMemberAdd() (role change) unexpected error: %v", err)
		}

		members, err := auth.OrgMembersList(ctx, org.ID)
		if err != nil {
			t.Fatalf("OrgMembersList() unexpected error: %v", err)
		}
		if len(members) != 1 {
			t.Fatalf("expected upsert to keep exactly 1 member row, got %d", len(members))
		}
		if members[0].RoleName != "org-member" {
			t.Errorf("expected role to be updated to 'org-member', got %q", members[0].RoleName)
		}
	})

	t.Run("OrgMemberAdd_UnknownRole", func(t *testing.T) {
		if err := auth.OrgMemberAdd(ctx, org.ID, user.ID, "does-not-exist"); err == nil {
			t.Error("expected error when granting an unknown role, got nil")
		}
	})

	t.Run("OrgMemberRemove", func(t *testing.T) {
		if err := auth.OrgMemberRemove(ctx, org.ID, user.ID); err != nil {
			t.Fatalf("OrgMemberRemove() unexpected error: %v", err)
		}
		members, err := auth.OrgMembersList(ctx, org.ID)
		if err != nil {
			t.Fatalf("OrgMembersList() unexpected error: %v", err)
		}
		if len(members) != 0 {
			t.Errorf("expected no members after removal, got %d", len(members))
		}
	})

	t.Run("OrganizationDelete_CascadesMembers", func(t *testing.T) {
		tempOrg, err := auth.OrganizationCreate(ctx, "Temp Org")
		if err != nil {
			t.Fatalf("OrganizationCreate() unexpected error: %v", err)
		}
		if err := auth.OrgMemberAdd(ctx, tempOrg.ID, user.ID, "org-owner"); err != nil {
			t.Fatalf("OrgMemberAdd() unexpected error: %v", err)
		}

		if err := auth.OrganizationDelete(ctx, tempOrg.ID); err != nil {
			t.Fatalf("OrganizationDelete() unexpected error: %v", err)
		}

		orgs, err := auth.UserOrganizationsList(ctx, user.ID)
		if err != nil {
			t.Fatalf("UserOrganizationsList() unexpected error: %v", err)
		}
		for _, o := range orgs {
			if o.ID == tempOrg.ID {
				t.Error("expected org_members row to be cascade-deleted with the organization")
			}
		}
	})

	t.Run("RoleDelete_CascadesOrgMembers", func(t *testing.T) {
		role, err := auth.RoleCreate(ctx, "temp-org-role", "")
		if err != nil {
			t.Fatalf("RoleCreate() unexpected error: %v", err)
		}
		if err := auth.OrgMemberAdd(ctx, org.ID, user.ID, "temp-org-role"); err != nil {
			t.Fatalf("OrgMemberAdd() unexpected error: %v", err)
		}

		if err := auth.RoleDelete(ctx, role.ID); err != nil {
			t.Fatalf("RoleDelete() unexpected error: %v", err)
		}

		members, err := auth.OrgMembersList(ctx, org.ID)
		if err != nil {
			t.Fatalf("OrgMembersList() unexpected error: %v", err)
		}
		for _, m := range members {
			if m.UserID == user.ID {
				t.Error("expected org_members row to be cascade-deleted with the role")
			}
		}
	})
}
