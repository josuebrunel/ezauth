-- +goose Up
-- +goose StatementBegin
-- Users table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    provider VARCHAR(50) NOT NULL DEFAULT 'local',
    provider_id VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    app_metadata JSON DEFAULT (JSON_OBJECT()),
    user_metadata JSON DEFAULT (JSON_OBJECT()),
    first_name VARCHAR(255) DEFAULT '',
    last_name VARCHAR(255) DEFAULT '',
    last_active_at TIMESTAMP NULL,
    locale VARCHAR(50) DEFAULT '',
    timezone VARCHAR(100) DEFAULT '',
    email_verified_at TIMESTAMP NULL,
    roles TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT unique_provider_user UNIQUE (provider, provider_id)
);

-- Indexes for users
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_provider ON users(provider, provider_id);

-- Tokens table
CREATE TABLE tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    token_type VARCHAR(50) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    metadata JSON DEFAULT (JSON_OBJECT()),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for tokens
CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_token ON tokens(token);
CREATE INDEX idx_tokens_type ON tokens(token_type);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tokens;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
