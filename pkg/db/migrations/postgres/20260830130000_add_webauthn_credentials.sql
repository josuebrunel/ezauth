-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES ezauth_users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports TEXT DEFAULT '',
    attestation_type TEXT DEFAULT '',
    name TEXT DEFAULT '',
    data JSONB DEFAULT '{}' :: jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_ezauth_webauthn_credentials_user_id ON ezauth_webauthn_credentials(user_id);

-- Ceremony challenges are stored separately from ezauth_tokens because a
-- discoverable (usernameless) login challenge has no known user yet, and
-- ezauth_tokens.user_id is a required, FK-enforced reference to ezauth_users.
CREATE TABLE IF NOT EXISTS ezauth_webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_key TEXT NOT NULL UNIQUE,
    challenge_type TEXT NOT NULL,
    user_id TEXT DEFAULT '',
    data JSONB DEFAULT '{}' :: jsonb,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ezauth_webauthn_challenges_session_key ON ezauth_webauthn_challenges(session_key);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_webauthn_challenges;
DROP TABLE IF EXISTS ezauth_webauthn_credentials;
-- +goose StatementEnd
