-- +goose Up
-- +goose StatementBegin
-- Audit-log rows were cascade-deleted with their user, erasing the audit
-- trail of what happened to (or via) an account right as it's deleted --
-- exactly the moment that trail matters most. Retain the row with a nulled
-- user reference instead: the event still happened and is still evidence,
-- even once the account itself is gone. See #212.
--
-- The init migration's FOREIGN KEY was unnamed, so MySQL auto-generated
-- ezauth_audit_logs_ibfk_1 for it; replaced here with an explicit name so
-- this migration's own Down (and any future one) doesn't have to guess it.
ALTER TABLE ezauth_audit_logs DROP FOREIGN KEY ezauth_audit_logs_ibfk_1;
ALTER TABLE ezauth_audit_logs MODIFY COLUMN user_id CHAR(32) NULL;
ALTER TABLE ezauth_audit_logs ADD CONSTRAINT ezauth_audit_logs_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE SET NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Any row that accumulated a NULL user_id while this migration was applied
-- (i.e. a user genuinely deleted in the meantime) can't be represented once
-- user_id is NOT NULL again -- deleting those rows is the only option,
-- mirroring how a real rollback of "stop losing this data" necessarily
-- loses whatever was preserved in between.
ALTER TABLE ezauth_audit_logs DROP FOREIGN KEY ezauth_audit_logs_user_id_fkey;
DELETE FROM ezauth_audit_logs WHERE user_id IS NULL;
ALTER TABLE ezauth_audit_logs MODIFY COLUMN user_id CHAR(32) NOT NULL;
ALTER TABLE ezauth_audit_logs ADD CONSTRAINT ezauth_audit_logs_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE;
-- +goose StatementEnd
