-- +goose Up
-- +goose StatementBegin
-- UsersList sorts newest first and the sign-ups count filters on created_at,
-- but this column had no index, so both scanned the whole users table (and
-- UsersList sorted all of it) on every request. With the index the newest
-- page is read straight off its end.
--
-- MySQL has no CREATE INDEX IF NOT EXISTS, so the ADD INDEX is guarded by an
-- information_schema existence check, like the other migrations.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND INDEX_NAME = 'idx_ezauth_users_created_at') = 0,
  'ALTER TABLE ezauth_users ADD INDEX idx_ezauth_users_created_at (created_at)',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND INDEX_NAME = 'idx_ezauth_users_created_at') > 0,
  'ALTER TABLE ezauth_users DROP INDEX idx_ezauth_users_created_at',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
