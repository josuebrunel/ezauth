-- +goose Up
-- +goose StatementBegin
-- Users table
CREATE TABLE IF NOT EXISTS ezauth_users (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    provider VARCHAR(50) NOT NULL DEFAULT 'local',
    provider_id VARCHAR(255),
    email_verified TINYINT(1) DEFAULT 0,
    app_metadata JSON DEFAULT (JSON_OBJECT()),
    user_metadata JSON DEFAULT (JSON_OBJECT()),
    first_name VARCHAR(255) DEFAULT '',
    last_name VARCHAR(255) DEFAULT '',
    last_active_at DATETIME,
    locale VARCHAR(10) DEFAULT '',
    timezone VARCHAR(50) DEFAULT '',
    email_verified_at DATETIME,
    roles VARCHAR(255) DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT unique_ezauth_provider_user UNIQUE (provider, provider_id),
    INDEX idx_ezauth_users_email (email),
    INDEX idx_ezauth_users_provider (provider, provider_id)
);

-- Tokens table
CREATE TABLE IF NOT EXISTS ezauth_tokens (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    user_id CHAR(32) NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    token_type VARCHAR(50) NOT NULL,
    -- 'access', 'refresh', 'passwordless'
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked TINYINT(1) DEFAULT 0,
    metadata JSON DEFAULT (JSON_OBJECT()),
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE,
    INDEX idx_ezauth_tokens_user_id (user_id),
    INDEX idx_ezauth_tokens_token (token),
    INDEX idx_ezauth_tokens_type (token_type),
    INDEX idx_ezauth_tokens_expires_at (expires_at)
);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_tokens;

DROP TABLE IF EXISTS ezauth_users;

-- +goose StatementEnd