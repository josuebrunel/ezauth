-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_organizations (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ezauth_org_members (
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES ezauth_organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES ezauth_roles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ezauth_org_members_user_id ON ezauth_org_members(user_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_org_members_role_id ON ezauth_org_members(role_id);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_org_members;

DROP TABLE IF EXISTS ezauth_organizations;

-- +goose StatementEnd
