-- +goose Up
-- +goose StatementBegin
ALTER TABLE ezauth_users ADD COLUMN last_login_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE ezauth_users ADD COLUMN phone VARCHAR(50) DEFAULT '';
ALTER TABLE ezauth_users ADD COLUMN phone_verified BOOLEAN DEFAULT FALSE;
ALTER TABLE ezauth_users ADD COLUMN is_active BOOLEAN DEFAULT TRUE;
ALTER TABLE ezauth_users ADD COLUMN avatar_url TEXT DEFAULT '';
ALTER TABLE ezauth_users ADD COLUMN nickname VARCHAR(255) DEFAULT '';
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
