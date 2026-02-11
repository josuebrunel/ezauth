-- +goose Up
-- +goose StatementBegin
-- Users table
CREATE TABLE IF NOT EXISTS ezauth_users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    provider TEXT NOT NULL DEFAULT 'local',
    provider_id TEXT,
    email_verified INTEGER DEFAULT 0,
    app_metadata TEXT DEFAULT '{}',
    user_metadata TEXT DEFAULT '{}',
    first_name TEXT DEFAULT '',
    last_name TEXT DEFAULT '',
    last_active_at DATETIME,
    locale TEXT DEFAULT '',
    timezone TEXT DEFAULT '',
    email_verified_at DATETIME,
    roles TEXT DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_ezauth_provider_user UNIQUE (provider, provider_id)
);

-- Indexes for users
CREATE INDEX IF NOT EXISTS idx_ezauth_users_email ON ezauth_users(email);

CREATE INDEX IF NOT EXISTS idx_ezauth_users_provider ON ezauth_users(provider, provider_id);

-- Tokens table
CREATE TABLE IF NOT EXISTS ezauth_tokens (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    token_type TEXT NOT NULL,
    -- 'access', 'refresh', 'passwordless'
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE
);

-- Indexes for tokens
CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_user_id ON ezauth_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_token ON ezauth_tokens(token);

CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_type ON ezauth_tokens(token_type);

CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_expires_at ON ezauth_tokens(expires_at);

-- Trigger to update updated_at (SQLite version)
CREATE TRIGGER IF NOT EXISTS update_ezauth_users_updated_at
AFTER
UPDATE
    ON ezauth_users BEGIN
UPDATE
    ezauth_users
SET
    updated_at = CURRENT_TIMESTAMP
WHERE
    id = NEW.id;

END;

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS update_ezauth_users_updated_at;

DROP TABLE IF EXISTS ezauth_tokens;

DROP TABLE IF EXISTS ezauth_users;

-- +goose StatementEnd