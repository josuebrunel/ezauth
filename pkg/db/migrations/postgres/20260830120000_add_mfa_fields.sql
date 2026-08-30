-- +goose Up
-- +goose StatementBegin
ALTER TABLE ezauth_users ADD COLUMN mfa_secret TEXT;
ALTER TABLE ezauth_users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users DROP COLUMN mfa_enabled;
ALTER TABLE ezauth_users DROP COLUMN mfa_secret;
-- +goose StatementEnd
