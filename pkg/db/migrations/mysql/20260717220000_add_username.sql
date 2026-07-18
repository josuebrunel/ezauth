-- +goose Up
-- +goose StatementBegin
ALTER TABLE ezauth_users ADD COLUMN username VARCHAR(255) DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users DROP COLUMN username;
-- +goose StatementEnd
