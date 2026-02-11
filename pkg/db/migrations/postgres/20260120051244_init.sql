-- +goose Up
-- +goose StatementBegin
-- Enable pgcrypto extension for UUID generation (more standard than uuid-ossp)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE IF NOT EXISTS ezauth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    provider VARCHAR(50) NOT NULL DEFAULT 'local',
    provider_id VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    app_metadata JSONB DEFAULT '{}' :: jsonb,
    user_metadata JSONB DEFAULT '{}' :: jsonb,
    first_name VARCHAR(255) DEFAULT '',
    last_name VARCHAR(255) DEFAULT '',
    last_active_at TIMESTAMP WITH TIME ZONE,
    locale VARCHAR(50) DEFAULT '',
    timezone VARCHAR(100) DEFAULT '',
    email_verified_at TIMESTAMP WITH TIME ZONE,
    roles TEXT DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_ezauth_provider_user UNIQUE (provider, provider_id)
);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_ezauth_users_email ON ezauth_users(email);

CREATE INDEX IF NOT EXISTS idx_ezauth_users_provider ON ezauth_users(provider, provider_id);

-- GIN indexes for JSONB columns to enable fast queries on metadata
CREATE INDEX IF NOT EXISTS idx_ezauth_users_app_metadata ON ezauth_users USING GIN (app_metadata);

CREATE INDEX IF NOT EXISTS idx_ezauth_users_user_metadata ON ezauth_users USING GIN (user_metadata);

-- Tokens table (replaces sessions)
CREATE TABLE IF NOT EXISTS ezauth_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES ezauth_users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    token_type VARCHAR(50) NOT NULL,
    -- 'access', 'refresh', 'passwordless'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}' :: jsonb
);

-- Indexes for tokens table
CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_user_id ON ezauth_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_token ON ezauth_tokens(token);

CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_type ON ezauth_tokens(token_type);

CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_expires_at ON ezauth_tokens(expires_at);

-- Function to update updated_at timestamp
CREATE
OR REPLACE FUNCTION update_updated_at_column() RETURNS TRIGGER AS $$ BEGIN NEW.updated_at = NOW();

RETURN NEW;

END;

$$ language 'plpgsql';

-- Trigger to automatically update updated_at
CREATE TRIGGER update_ezauth_users_updated_at BEFORE
UPDATE
    ON ezauth_users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments for documentation
COMMENT ON TABLE ezauth_users IS 'User accounts with support for multiple authentication providers';

COMMENT ON COLUMN ezauth_users.app_metadata IS 'Application-controlled metadata (admin-only updates)';

COMMENT ON COLUMN ezauth_users.user_metadata IS 'User-controlled metadata (user can update)';

COMMENT ON TABLE ezauth_tokens IS 'Authentication tokens including access, refresh, and passwordless tokens';

COMMENT ON COLUMN ezauth_tokens.token_type IS 'Type of token: access, refresh, or passwordless';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS update_ezauth_users_updated_at ON ezauth_users;

DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TABLE IF EXISTS ezauth_tokens;

DROP TABLE IF EXISTS ezauth_users;

DROP EXTENSION IF EXISTS "pgcrypto";

-- +goose StatementEnd
