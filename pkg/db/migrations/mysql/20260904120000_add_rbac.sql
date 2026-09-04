-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_roles (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ezauth_permissions (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ezauth_role_permissions (
    role_id CHAR(32) NOT NULL,
    permission_id CHAR(32) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES ezauth_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES ezauth_permissions(id) ON DELETE CASCADE,
    INDEX idx_ezauth_role_permissions_permission_id (permission_id)
);

CREATE TABLE IF NOT EXISTS ezauth_user_roles (
    user_id CHAR(32) NOT NULL,
    role_id CHAR(32) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES ezauth_roles(id) ON DELETE CASCADE,
    INDEX idx_ezauth_user_roles_role_id (role_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_user_roles;
DROP TABLE IF EXISTS ezauth_role_permissions;
DROP TABLE IF EXISTS ezauth_permissions;
DROP TABLE IF EXISTS ezauth_roles;
-- +goose StatementEnd
