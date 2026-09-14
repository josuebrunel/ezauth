-- +goose Up
-- +goose StatementBegin
-- Audit-log rows were cascade-deleted with their user, erasing the audit
-- trail of what happened to (or via) an account right as it's deleted --
-- exactly the moment that trail matters most. Retain the row with a nulled
-- user reference instead: the event still happened and is still evidence,
-- even once the account itself is gone. See #212.
--
-- SQLite has no ALTER COLUMN or ALTER ... ADD/DROP CONSTRAINT -- both the
-- NOT NULL relaxation and the ON DELETE CASCADE -> SET NULL change require
-- rebuilding the table (the documented approach for schema changes SQLite's
-- ALTER TABLE can't express directly).
CREATE TABLE ezauth_audit_logs_new (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT,
    event_type TEXT NOT NULL,
    metadata TEXT DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE SET NULL
);

INSERT INTO ezauth_audit_logs_new (id, user_id, event_type, metadata, created_at)
SELECT id, user_id, event_type, metadata, created_at FROM ezauth_audit_logs;

DROP TABLE ezauth_audit_logs;

ALTER TABLE ezauth_audit_logs_new RENAME TO ezauth_audit_logs;

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_user_id ON ezauth_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_event_type ON ezauth_audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_created_at ON ezauth_audit_logs(created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Any row that accumulated a NULL user_id while this migration was applied
-- (i.e. a user genuinely deleted in the meantime) can't be represented once
-- user_id is NOT NULL again -- deleting those rows is the only option,
-- mirroring how a real rollback of "stop losing this data" necessarily
-- loses whatever was preserved in between.
CREATE TABLE ezauth_audit_logs_old (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    metadata TEXT DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE
);

INSERT INTO ezauth_audit_logs_old (id, user_id, event_type, metadata, created_at)
SELECT id, user_id, event_type, metadata, created_at FROM ezauth_audit_logs WHERE user_id IS NOT NULL;

DROP TABLE ezauth_audit_logs;

ALTER TABLE ezauth_audit_logs_old RENAME TO ezauth_audit_logs;

CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_user_id ON ezauth_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_event_type ON ezauth_audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_ezauth_audit_logs_created_at ON ezauth_audit_logs(created_at);
-- +goose StatementEnd
