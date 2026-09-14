-- +goose Up
-- +goose StatementBegin
-- MySQL's DDL isn't transactional and has no ADD/DROP COLUMN IF [NOT]
-- EXISTS clause (that's a MariaDB-only extension) -- a mid-migration
-- failure can leave a column partially applied, and simply re-running the
-- plain ALTER TABLE then fails with "Duplicate column name" instead of
-- completing the retry. Guard every ADD/DROP COLUMN and ADD/DROP INDEX in
-- these mysql migrations with an information_schema existence check
-- through PREPARE/EXECUTE, so re-running a migration (after fixing
-- whatever caused a partial failure) is a safe no-op instead of an error.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'username') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN username VARCHAR(255) DEFAULT ''''',
  'SELECT 1'
));
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'username') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN username',
  'SELECT 1'
));
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
