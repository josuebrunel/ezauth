-- +goose Up
-- +goose StatementBegin
-- Ceremony challenges are only ever deleted on successful completion
-- (WebauthnFinishRegistration/WebauthnFinishLogin) -- an abandoned
-- registration/login ceremony leaves its row forever. This index supports
-- WebauthnChallengeDeleteExpired, which callers can invoke periodically
-- (e.g. from their own cron/scheduler) to prune those rows; without it,
-- that cleanup query would be a full table scan.
--
-- See 20260717220000_add_username.sql for why the ADD INDEX here is guarded
-- by an information_schema existence check.
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_webauthn_challenges' AND INDEX_NAME = 'idx_ezauth_webauthn_challenges_expires_at') = 0,
  'ALTER TABLE ezauth_webauthn_challenges ADD INDEX idx_ezauth_webauthn_challenges_expires_at (expires_at)',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET @stmt := (SELECT IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'ezauth_webauthn_challenges' AND INDEX_NAME = 'idx_ezauth_webauthn_challenges_expires_at') > 0,
  'ALTER TABLE ezauth_webauthn_challenges DROP INDEX idx_ezauth_webauthn_challenges_expires_at',
  'SELECT 1'
));
PREPARE stmt FROM @stmt; EXECUTE stmt; DEALLOCATE PREPARE stmt;
-- +goose StatementEnd
