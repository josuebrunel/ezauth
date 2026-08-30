-- +goose Up
-- +goose StatementBegin
ALTER TABLE ezauth_users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ezauth_users ADD COLUMN locked_until DATETIME;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users DROP COLUMN locked_until;
ALTER TABLE ezauth_users DROP COLUMN failed_login_attempts;
-- +goose StatementEnd
