-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ezauth_org_members (
    org_id UUID NOT NULL REFERENCES ezauth_organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES ezauth_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES ezauth_roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_ezauth_org_members_user_id ON ezauth_org_members(user_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_org_members_role_id ON ezauth_org_members(role_id);

COMMENT ON TABLE ezauth_organizations IS 'Multi-tenant organizations/teams.';

COMMENT ON TABLE ezauth_org_members IS 'Per-(user, org) role assignment, drawn from the ezauth_roles catalog.';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_org_members;

DROP TABLE IF EXISTS ezauth_organizations;

-- +goose StatementEnd
