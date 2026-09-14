-- +goose Up
-- +goose StatementBegin
-- See 20260717220000_add_username.sql for why every ADD/DROP COLUMN here is
-- guarded by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'last_login_at') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN last_login_at DATETIME',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'phone') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN phone VARCHAR(50) DEFAULT ''''',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'phone_verified') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN phone_verified TINYINT(1) DEFAULT 0',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'is_active') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN is_active TINYINT(1) DEFAULT 1',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'avatar_url') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN avatar_url VARCHAR(500) DEFAULT ''''',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'nickname') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN nickname VARCHAR(255) DEFAULT ''''',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'nickname') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN nickname',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'avatar_url') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN avatar_url',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'is_active') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN is_active',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'phone_verified') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN phone_verified',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'phone') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN phone',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'last_login_at') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN last_login_at',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
