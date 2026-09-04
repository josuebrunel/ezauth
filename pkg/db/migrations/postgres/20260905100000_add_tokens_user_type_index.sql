-- +goose Up
-- +goose StatementBegin
-- QueryTokenListByUserIDAndType filters on both columns together (backing
-- Sessions, TrustedDevices, Invitations, APIKeysList, RevokeAllSessions) but
-- only single-column indexes existed on user_id and token_type separately.
CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_user_id_type ON ezauth_tokens(user_id, token_type);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_ezauth_tokens_user_id_type;
-- +goose StatementEnd
