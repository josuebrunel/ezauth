-- +goose Up
-- +goose StatementBegin
-- Partial unique index: multiple users may have an empty phone ('' default),
-- but no two users may share the same non-empty phone number.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ezauth_users_phone_unique ON ezauth_users(phone) WHERE phone <> '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_ezauth_users_phone_unique;
-- +goose StatementEnd
