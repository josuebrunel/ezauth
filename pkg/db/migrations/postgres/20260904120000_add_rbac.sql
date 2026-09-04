-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ezauth_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ezauth_role_permissions (
    role_id UUID NOT NULL REFERENCES ezauth_roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES ezauth_permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS ezauth_user_roles (
    user_id UUID NOT NULL REFERENCES ezauth_users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES ezauth_roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_ezauth_role_permissions_permission_id ON ezauth_role_permissions(permission_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_user_roles_role_id ON ezauth_user_roles(role_id);

COMMENT ON TABLE ezauth_roles IS 'Real RBAC roles (many-to-many with users via ezauth_user_roles).';

COMMENT ON TABLE ezauth_permissions IS 'Real RBAC permissions (many-to-many with roles via ezauth_role_permissions).';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_user_roles;

DROP TABLE IF EXISTS ezauth_role_permissions;

DROP TABLE IF EXISTS ezauth_permissions;

DROP TABLE IF EXISTS ezauth_roles;

-- +goose StatementEnd
