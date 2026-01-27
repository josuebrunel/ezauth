-- +goose Up
-- +goose StatementBegin
-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    provider TEXT NOT NULL DEFAULT 'local',
    provider_id TEXT,
    email_verified INTEGER DEFAULT 0,
    app_metadata TEXT DEFAULT '{}',
    user_metadata TEXT DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_provider_user UNIQUE (provider, provider_id)
);

-- Indexes for users
CREATE INDEX idx_users_email ON users(email);

CREATE INDEX idx_users_provider ON users(provider, provider_id);

-- Tokens table
CREATE TABLE tokens (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    token_type TEXT NOT NULL,
    -- 'access', 'refresh', 'passwordless'
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked INTEGER DEFAULT 0,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for tokens
CREATE INDEX idx_tokens_user_id ON tokens(user_id);

CREATE INDEX idx_tokens_token ON tokens(token);

CREATE INDEX idx_tokens_type ON tokens(token_type);

CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);

-- Passwordless tokens table
-- Trigger to update updated_at (SQLite version)
CREATE TRIGGER update_users_updated_at
AFTER
UPDATE
    ON users BEGIN
UPDATE
    users
SET
    updated_at = CURRENT_TIMESTAMP
WHERE
    id = NEW.id;

END;

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS update_users_updated_at;

DROP TABLE IF EXISTS tokens;

DROP TABLE IF EXISTS users;

-- +goose StatementEnd