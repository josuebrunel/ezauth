-- +goose Up
-- +goose StatementBegin
-- MySQL has no partial/filtered unique index, so use a generated column that's
-- NULL for an empty phone (multiple NULLs are allowed in a unique index) and
-- the phone value otherwise, then index that instead of the phone column.
-- INVISIBLE (8.0.23+) keeps it out of `SELECT *`, so it doesn't break the
-- existing "SELECT * -> struct scan" query pattern used throughout the repository layer.
--
-- See 20260717220000_add_username.sql for why the ADD COLUMN/ADD INDEX here
-- are guarded by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'phone_unique_key') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN phone_unique_key VARCHAR(50) GENERATED ALWAYS AS (NULLIF(phone, '''')) VIRTUAL INVISIBLE',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND INDEX_NAME = 'idx_ezauth_users_phone_unique') = 0,
  'ALTER TABLE ezauth_users ADD UNIQUE INDEX idx_ezauth_users_phone_unique (phone_unique_key)',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND INDEX_NAME = 'idx_ezauth_users_phone_unique') > 0,
  'ALTER TABLE ezauth_users DROP INDEX idx_ezauth_users_phone_unique',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'phone_unique_key') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN phone_unique_key',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
