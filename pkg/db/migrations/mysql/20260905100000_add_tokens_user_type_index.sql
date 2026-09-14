-- +goose Up
-- +goose StatementBegin
-- QueryTokenListByUserIDAndType filters on both columns together (backing
-- Sessions, TrustedDevices, Invitations, APIKeysList, RevokeAllSessions) but
-- only single-column indexes existed on user_id and token_type separately.
--
-- See 20260717220000_add_username.sql for why the ADD INDEX here is guarded
-- by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_tokens' AND INDEX_NAME = 'idx_ezauth_tokens_user_id_type') = 0,
  'ALTER TABLE ezauth_tokens ADD INDEX idx_ezauth_tokens_user_id_type (user_id, token_type)',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_tokens' AND INDEX_NAME = 'idx_ezauth_tokens_user_id_type') > 0,
  'ALTER TABLE ezauth_tokens DROP INDEX idx_ezauth_tokens_user_id_type',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
