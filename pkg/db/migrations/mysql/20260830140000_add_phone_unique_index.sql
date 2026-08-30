-- +goose Up
-- +goose StatementBegin
-- MySQL has no partial/filtered unique index, so use a generated column that's
-- NULL for an empty phone (multiple NULLs are allowed in a unique index) and
-- the phone value otherwise, then index that instead of the phone column.
-- INVISIBLE (8.0.23+) keeps it out of `SELECT *`, so it doesn't break the
-- existing "SELECT * -> struct scan" query pattern used throughout the repository layer.
ALTER TABLE ezauth_users ADD COLUMN phone_unique_key VARCHAR(50) GENERATED ALWAYS AS (NULLIF(phone, '')) VIRTUAL INVISIBLE;
ALTER TABLE ezauth_users ADD UNIQUE INDEX idx_ezauth_users_phone_unique (phone_unique_key);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users DROP INDEX idx_ezauth_users_phone_unique;
ALTER TABLE ezauth_users DROP COLUMN phone_unique_key;
-- +goose StatementEnd
