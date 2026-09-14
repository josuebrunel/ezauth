-- +goose Up
-- +goose StatementBegin
-- Tracks the last TOTP timestep accepted for this user, so
-- mfaValidateAnyCode can reject a timestep that already succeeded once
-- (RFC 6238 §5.2) instead of letting a captured code stay usable for the
-- rest of its ~30s validity window (plus skew).
--
-- See 20260717220000_add_username.sql for why the ADD COLUMN here is
-- guarded by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'mfa_last_totp_counter') = 0,
  'ALTER TABLE ezauth_users ADD COLUMN mfa_last_totp_counter BIGINT',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_users' AND COLUMN_NAME = 'mfa_last_totp_counter') > 0,
  'ALTER TABLE ezauth_users DROP COLUMN mfa_last_totp_counter',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
