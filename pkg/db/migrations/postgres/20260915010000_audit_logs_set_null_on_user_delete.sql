-- +goose Up
-- +goose StatementBegin
-- Audit-log rows were cascade-deleted with their user, erasing the audit
-- trail of what happened to (or via) an account right as it's deleted --
-- exactly the moment that trail matters most. Retain the row with a nulled
-- user reference instead: the event still happened and is still evidence,
-- even once the account itself is gone. See #212.
--
-- The init migration's FK is unnamed, so postgres auto-generates its name
-- (conventionally <table>_<column>_fkey); looked up dynamically rather than
-- assumed, so this doesn't depend on that naming convention holding.
DO $$
DECLARE
    conname text;
BEGIN
    SELECT tc.constraint_name INTO conname
    FROM information_schema.table_constraints tc
    WHERE tc.table_name = 'ezauth_audit_logs'
      AND tc.constraint_type = 'FOREIGN KEY';
    EXECUTE format('ALTER TABLE ezauth_audit_logs DROP CONSTRAINT %I', conname);
END $$;

ALTER TABLE ezauth_audit_logs ALTER COLUMN user_id DROP NOT NULL;
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
ALTER TABLE ezauth_audit_logs DROP CONSTRAINT ezauth_audit_logs_user_id_fkey;
DELETE FROM ezauth_audit_logs WHERE user_id IS NULL;
ALTER TABLE ezauth_audit_logs ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE ezauth_audit_logs ADD CONSTRAINT ezauth_audit_logs_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES ezauth_users(id) ON DELETE CASCADE;
-- +goose StatementEnd
