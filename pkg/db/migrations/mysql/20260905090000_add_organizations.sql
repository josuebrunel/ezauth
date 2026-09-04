-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_organizations (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    name VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ezauth_org_members (
    org_id CHAR(32) NOT NULL,
    user_id CHAR(32) NOT NULL,
    role_id CHAR(32) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES ezauth_organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES ezauth_roles(id) ON DELETE CASCADE,
    INDEX idx_ezauth_org_members_user_id (user_id),
    INDEX idx_ezauth_org_members_role_id (role_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_org_members;
DROP TABLE IF EXISTS ezauth_organizations;
-- +goose StatementEnd
