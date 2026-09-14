-- +goose Up
-- +goose StatementBegin
-- Normalize existing username casing to lowercase (a no-op in practice under
-- MySQL's default case-insensitive collation, since the WHERE clause below
-- never matches -- kept for parity with postgres/sqlite and in case this
-- column was ever created with a case-sensitive collation).
UPDATE ezauth_users
SET username = LOWER(username)
WHERE username <> '' AND username <> LOWER(username);

-- Resolve any pre-existing duplicate usernames (including case-variant
-- duplicates, which already collide under MySQL's default _ci collation) so
-- the unique index below can't fail to create: keep the lowest-id row
-- untouched and suffix every other row sharing that username with its own
-- id (guaranteed unique, unlike a truncated substring). A self-join, not a
-- subquery on the same table, since MySQL rejects
-- "UPDATE t ... WHERE EXISTS (SELECT ... FROM t)" on the table being updated.
UPDATE ezauth_users u1
JOIN ezauth_users u2 ON u2.username = u1.username AND u2.id <> u1.id AND u2.id < u1.id
SET u1.username = CONCAT(u1.username, '_', u1.id)
WHERE u1.username <> '';

-- MySQL has no partial/filtered unique index, so use a generated column
-- that's NULL for an empty username (multiple NULLs are allowed in a unique
-- index) and the username value otherwise, then index that instead of the
-- username column directly. It inherits the column's default collation, so
-- this is case-insensitive on MySQL like the rest of this migration.
-- INVISIBLE (8.0.23+) keeps it out of `SELECT *`, so it doesn't break the
-- existing "SELECT * -> struct scan" query pattern used throughout the
-- repository layer.
--
-- See 20260717220000_add_username.sql for why the ADD COLUMN/ADD INDEX here
-- are guarded by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'username_unique_key') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN username_unique_key VARCHAR(255) GENERATED ALWAYS AS (NULLIF(username, '''')) VIRTUAL INVISIBLE',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND INDEX_NAME = 'idx_ezauth_users_username_unique') = 0,
  'ALTER TABLE ezauth_users ADD UNIQUE INDEX idx_ezauth_users_username_unique (username_unique_key)',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND INDEX_NAME = 'idx_ezauth_users_username_unique') > 0,
  'ALTER TABLE ezauth_users DROP INDEX idx_ezauth_users_username_unique',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'username_unique_key') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN username_unique_key',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
