-- +goose Up
-- +goose StatementBegin
-- Ceremony challenges are only ever deleted on successful completion
-- (WebauthnFinishRegistration/WebauthnFinishLogin) -- an abandoned
-- registration/login ceremony leaves its row forever. This index supports
-- WebauthnChallengeDeleteExpired, which callers can invoke periodically
-- (e.g. from their own cron/scheduler) to prune those rows; without it,
-- that cleanup query would be a full table scan.
CREATE INDEX IF NOT EXISTS idx_ezauth_webauthn_challenges_expires_at ON ezauth_webauthn_challenges(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_ezauth_webauthn_challenges_expires_at;
-- +goose StatementEnd
