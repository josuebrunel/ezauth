-- +goose Up
CREATE TABLE users (
    id CHAR(36) PRIMARY KEY,
    instance_id CHAR(36),
    aud VARCHAR(255),
    role VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    encrypted_password VARCHAR(255),
    email_confirmed_at TIMESTAMP NULL,
    invited_at TIMESTAMP NULL,
    confirmation_token VARCHAR(255),
    confirmation_sent_at TIMESTAMP NULL,
    recovery_token VARCHAR(255),
    recovery_sent_at TIMESTAMP NULL,
    email_change_token_new VARCHAR(255),
    email_change VARCHAR(255),
    email_change_sent_at TIMESTAMP NULL,
    last_sign_in_at TIMESTAMP NULL,
    raw_app_meta_data JSON,
    raw_user_meta_data JSON,
    is_super_admin BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    phone VARCHAR(15) UNIQUE,
    phone_confirmed_at TIMESTAMP NULL,
    phone_change VARCHAR(15),
    phone_change_token VARCHAR(255),
    phone_change_sent_at TIMESTAMP NULL,
    confirmed_at TIMESTAMP NULL,
    email_change_token_current VARCHAR(255),
    email_change_confirm_status SMALLINT,
    banned_until TIMESTAMP NULL,
    reauthentication_token VARCHAR(255),
    reauthentication_sent_at TIMESTAMP NULL,
    is_sso_user BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMP NULL
);

CREATE TABLE identities (
    id VARCHAR(255) NOT NULL,
    user_id CHAR(36) NOT NULL,
    identity_data JSON NOT NULL,
    provider VARCHAR(50) NOT NULL,
    last_sign_in_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    email VARCHAR(255),
    PRIMARY KEY (provider, id),
    CONSTRAINT identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE sessions (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    factor_id CHAR(36),
    aal VARCHAR(20),
    not_after TIMESTAMP NULL,
    refreshed_at TIMESTAMP NULL,
    user_agent TEXT,
    ip TEXT,
    tag VARCHAR(255),
    CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id CHAR(36) NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    parent VARCHAR(255),
    session_id CHAR(36),
    CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE audit_log_entries (
    id CHAR(36) PRIMARY KEY,
    instance_id CHAR(36),
    payload JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(64) NOT NULL DEFAULT ''
);

-- Note: email and token indices are created automatically by UNIQUE constraints
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE INDEX identities_user_id_idx ON identities (user_id);

-- +goose Down
DROP TABLE IF EXISTS audit_log_entries;

DROP TABLE IF EXISTS refresh_tokens;

DROP TABLE IF EXISTS sessions;

DROP TABLE IF EXISTS identities;

DROP TABLE IF EXISTS users;