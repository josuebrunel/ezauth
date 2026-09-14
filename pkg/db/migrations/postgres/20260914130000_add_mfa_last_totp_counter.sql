-- +goose Up
-- +goose StatementBegin
-- Tracks the last TOTP timestep accepted for this user, so
-- mfaValidateAnyCode can reject a timestep that already succeeded once
-- (RFC 6238 §5.2) instead of letting a captured code stay usable for the
-- rest of its ~30s validity window (plus skew).
ALTER TABLE ezauth_users ADD COLUMN mfa_last_totp_counter BIGINT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users DROP COLUMN mfa_last_totp_counter;
-- +goose StatementEnd
