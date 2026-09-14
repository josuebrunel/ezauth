-- +goose Up
-- +goose StatementBegin
-- See 20260717220000_add_username.sql for why every ADD/DROP COLUMN here is
-- guarded by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'failed_login_attempts') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN failed_login_attempts INT NOT NULL DEFAULT 0',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'locked_until') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN locked_until DATETIME',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'locked_until') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN locked_until',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'failed_login_attempts') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN failed_login_attempts',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
