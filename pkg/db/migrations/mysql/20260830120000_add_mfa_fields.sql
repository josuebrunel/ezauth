-- +goose Up
-- +goose StatementBegin
ALTER TABLE ezauth_users ADD COLUMN mfa_secret VARCHAR(255);
ALTER TABLE ezauth_users ADD COLUMN mfa_enabled TINYINT(1) DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users DROP COLUMN mfa_enabled;
ALTER TABLE ezauth_users DROP COLUMN mfa_secret;
-- +goose StatementEnd
