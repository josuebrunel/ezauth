-- +goose Up
-- +goose StatementBegin
ALTER TABLE ezauth_users ADD COLUMN last_login_at DATETIME;
ALTER TABLE ezauth_users ADD COLUMN phone TEXT DEFAULT '';
ALTER TABLE ezauth_users ADD COLUMN phone_verified INTEGER DEFAULT 0;
ALTER TABLE ezauth_users ADD COLUMN is_active INTEGER DEFAULT 1;
ALTER TABLE ezauth_users ADD COLUMN avatar_url TEXT DEFAULT '';
ALTER TABLE ezauth_users ADD COLUMN nickname TEXT DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users DROP COLUMN nickname;
ALTER TABLE ezauth_users DROP COLUMN avatar_url;
ALTER TABLE ezauth_users DROP COLUMN is_active;
ALTER TABLE ezauth_users DROP COLUMN phone_verified;
ALTER TABLE ezauth_users DROP COLUMN phone;
ALTER TABLE ezauth_users DROP COLUMN last_login_at;
-- +goose StatementEnd
