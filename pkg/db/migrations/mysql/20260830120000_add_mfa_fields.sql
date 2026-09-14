-- +goose Up
-- +goose StatementBegin
-- See 20260717220000_add_username.sql for why every ADD/DROP COLUMN here is
-- guarded by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'mfa_secret') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN mfa_secret VARCHAR(255)',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'mfa_enabled') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN mfa_enabled TINYINT(1) DEFAULT 0',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'mfa_enabled') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN mfa_enabled',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'mfa_secret') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN mfa_secret',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
