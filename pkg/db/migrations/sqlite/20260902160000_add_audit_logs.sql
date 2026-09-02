-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_audit_logs (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    metadata TEXT DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_user_id ON ezauth_audit_logs(user_id);

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_event_type ON ezauth_audit_logs(event_type);

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_created_at ON ezauth_audit_logs(created_at);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_audit_logs;

-- +goose StatementEnd
