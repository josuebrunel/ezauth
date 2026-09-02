-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ezauth_audit_logs (
    id CHAR(32) PRIMARY KEY DEFAULT (REPLACE(UUID(), '-', '')),
    user_id CHAR(32) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    metadata JSON DEFAULT (JSON_OBJECT()),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE,
    INDEX idx_ezauth_audit_logs_user_id (user_id),
    INDEX idx_ezauth_audit_logs_event_type (event_type),
    INDEX idx_ezauth_audit_logs_created_at (created_at)
);
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ezauth_audit_logs;
-- +goose StatementEnd
