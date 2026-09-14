-- +goose Up
-- +goose StatementBegin
-- Hash existing bearer-style token values in place, matching the app-level
-- change (see util.HashToken): refresh, password-reset, passwordless,
-- API-key, MFA-pre-auth, trusted-device, invitation, and email-change
-- tokens were previously stored and looked up as plaintext. mfa_recovery
-- and sms_otp rows are already hashed the same way (SHA-256, unsalted --
-- these are high-entropy random values, not passwords) and must be left
-- alone, or they'd be double-hashed and stop matching on lookup.
--
-- Hashing in place here means existing sessions/API keys/etc. keep working
-- after this deploys: the app now hashes an incoming raw value before
-- looking it up, so as long as the stored value already reflects that same
-- hash, nothing needs to be reissued.
--
-- Requires pgcrypto for digest(); this is a standard, widely available
-- extension (part of the postgres "contrib" set), not a third-party one.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

UPDATE ezauth_tokens
SET token = encode(digest(token, 'sha256'), 'hex')
WHERE token_type NOT IN ('mfa_recovery', 'sms_otp');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1; -- original plaintext values can't be recovered from their hash; intentional no-op
-- +goose StatementEnd
