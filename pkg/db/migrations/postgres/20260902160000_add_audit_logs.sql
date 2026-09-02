-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES ezauth_users(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    metadata JSONB DEFAULT '{}' :: jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_user_id ON ezauth_audit_logs(user_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_event_type ON ezauth_audit_logs(event_type);

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_created_at ON ezauth_audit_logs(created_at);

COMMENT ON TABLE ezauth_audit_logs IS 'Persisted security-relevant auth events (login, password reset, impersonation, lockout, etc.)';

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_audit_logs;

-- +goose StatementEnd
