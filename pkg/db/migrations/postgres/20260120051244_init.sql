-- +goose Up
-- +goose StatementBegin
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    provider VARCHAR(50) NOT NULL DEFAULT 'local',
    provider_id VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    app_metadata JSONB DEFAULT '{}' :: jsonb,
    user_metadata JSONB DEFAULT '{}' :: jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_provider_user UNIQUE (provider, provider_id)
);

-- Create index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);

CREATE INDEX idx_users_provider ON users(provider, provider_id);

-- GIN indexes for JSONB columns to enable fast queries on metadata
CREATE INDEX idx_users_app_metadata ON users USING GIN (app_metadata);

CREATE INDEX idx_users_user_metadata ON users USING GIN (user_metadata);

-- Tokens table (replaces sessions)
CREATE TABLE tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    token_type VARCHAR(50) NOT NULL,
    -- 'access', 'refresh', 'passwordless'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}' :: jsonb
);

-- Indexes for tokens table
CREATE INDEX idx_tokens_user_id ON tokens(user_id);

CREATE INDEX idx_tokens_token ON tokens(token);

CREATE INDEX idx_tokens_type ON tokens(token_type);

CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);

-- Passwordless tokens table
-- Function to update updated_at timestamp
CREATE
OR REPLACE FUNCTION update_updated_at_column() RETURNS TRIGGER AS $$ BEGIN NEW.updated_at = NOW();

RETURN NEW;

END;

$$ language 'plpgsql';

-- Trigger to automatically update updated_at
CREATE TRIGGER update_users_updated_at BEFORE
UPDATE
    ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments for documentation
COMMENT ON TABLE users IS 'User accounts with support for multiple authentication providers';

COMMENT ON COLUMN users.app_metadata IS 'Application-controlled metadata (admin-only updates)';

COMMENT ON COLUMN users.user_metadata IS 'User-controlled metadata (user can update)';

COMMENT ON TABLE tokens IS 'Authentication tokens including access, refresh, and passwordless tokens';

COMMENT ON COLUMN tokens.token_type IS 'Type of token: access, refresh, or passwordless';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TABLE IF EXISTS tokens;

DROP TABLE IF EXISTS users;

DROP EXTENSION IF EXISTS "uuid-ossp";

-- +goose StatementEnd
