-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    instance_id TEXT,
    aud TEXT,
    role TEXT,
    email TEXT UNIQUE,
    encrypted_password TEXT,
    email_confirmed_at DATETIME,
    invited_at DATETIME,
    confirmation_token TEXT,
    confirmation_sent_at DATETIME,
    recovery_token TEXT,
    recovery_sent_at DATETIME,
    email_change_token_new TEXT,
    email_change TEXT,
    email_change_sent_at DATETIME,
    last_sign_in_at DATETIME,
    raw_app_meta_data TEXT,
    raw_user_meta_data TEXT,
    is_super_admin BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    phone TEXT UNIQUE,
    phone_confirmed_at DATETIME,
    phone_change TEXT,
    phone_change_token TEXT,
    phone_change_sent_at DATETIME,
    confirmed_at DATETIME,
    email_change_token_current TEXT,
    email_change_confirm_status INTEGER,
    banned_until DATETIME,
    reauthentication_token TEXT,
    reauthentication_sent_at DATETIME,
    is_sso_user BOOLEAN DEFAULT 0,
    deleted_at DATETIME
);

CREATE TABLE identities (
    id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    identity_data TEXT NOT NULL,
    provider TEXT NOT NULL,
    last_sign_in_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    email TEXT,
    PRIMARY KEY (provider, id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    factor_id TEXT,
    aal TEXT,
    not_after DATETIME,
    refreshed_at DATETIME,
    user_agent TEXT,
    ip TEXT,
    tag TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    revoked BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    parent TEXT,
    session_id TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE audit_log_entries (
    id TEXT PRIMARY KEY,
    instance_id TEXT,
    payload TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NOT NULL DEFAULT ''
);

CREATE INDEX users_email_idx ON users (email);

CREATE INDEX refresh_tokens_token_idx ON refresh_tokens (token);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE INDEX identities_user_id_idx ON identities (user_id);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_log_entries;

DROP TABLE IF EXISTS refresh_tokens;

DROP TABLE IF EXISTS sessions;

DROP TABLE IF EXISTS identities;

DROP TABLE IF EXISTS users;

-- +goose StatementEnd