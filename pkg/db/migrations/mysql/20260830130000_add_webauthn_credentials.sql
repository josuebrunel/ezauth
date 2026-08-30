-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_webauthn_credentials (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    user_id CHAR(32) NOT NULL,
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
    transports VARCHAR(255) DEFAULT '',
    attestation_type VARCHAR(50) DEFAULT '',
    name VARCHAR(255) DEFAULT '',
    data JSON DEFAULT (JSON_OBJECT()),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE,
    INDEX idx_ezauth_webauthn_credentials_user_id (user_id)
);

-- Ceremony challenges are stored separately from ezauth_tokens because a
-- discoverable (usernameless) login challenge has no known user yet, and
-- ezauth_tokens.user_id is a required, FK-enforced reference to ezauth_users.
CREATE TABLE IF NOT EXISTS ezauth_webauthn_challenges (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    session_key VARCHAR(255) NOT NULL UNIQUE,
    challenge_type VARCHAR(50) NOT NULL,
    user_id CHAR(32) DEFAULT '',
    data JSON DEFAULT (JSON_OBJECT()),
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_webauthn_challenges;
DROP TABLE IF EXISTS ezauth_webauthn_credentials;
-- +goose StatementEnd
