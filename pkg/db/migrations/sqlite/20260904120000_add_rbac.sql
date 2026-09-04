-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_roles (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ezauth_permissions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ezauth_role_permissions (
    role_id TEXT NOT NULL,
    permission_id TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES ezauth_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES ezauth_permissions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ezauth_user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES ezauth_roles(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ezauth_role_permissions_permission_id ON ezauth_role_permissions(permission_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_user_roles_role_id ON ezauth_user_roles(role_id);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_user_roles;

DROP TABLE IF EXISTS ezauth_role_permissions;

DROP TABLE IF EXISTS ezauth_permissions;

DROP TABLE IF EXISTS ezauth_roles;

-- +goose StatementEnd
