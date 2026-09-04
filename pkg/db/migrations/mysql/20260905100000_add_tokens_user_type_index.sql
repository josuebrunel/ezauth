-- +goose Up
-- +goose StatementBegin
-- QueryTokenListByUserIDAndType filters on both columns together (backing
-- Sessions, TrustedDevices, Invitations, APIKeysList, RevokeAllSessions) but
-- only single-column indexes existed on user_id and token_type separately.
ALTER TABLE ezauth_tokens ADD INDEX idx_ezauth_tokens_user_id_type (user_id, token_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_tokens DROP INDEX idx_ezauth_tokens_user_id_type;
-- +goose StatementEnd
