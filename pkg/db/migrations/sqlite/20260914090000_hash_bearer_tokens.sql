-- +goose Up
-- +goose StatementBegin
-- Hash existing bearer-style token values in place, matching the app-level
-- change (see util.HashToken): refresh, password-reset, passwordless,
-- API-key, MFA-pre-auth, trusted-device, invitation, and email-change
-- tokens were previously stored and looked up as plaintext.
--
-- Unlike the postgres (pgcrypto's digest()) and mysql (SHA2()) versions of
-- this migration, SQLite has no built-in cryptographic hash function, and
-- the pure-Go driver this project uses (modernc.org/sqlite) doesn't load C
-- extensions that could add one -- there's no portable way to hash
-- existing rows in place from SQL alone here.
--
-- This is intentionally a no-op. Practically: any refresh token, password-
-- reset link, passwordless link, API key, MFA pre-auth token, trusted-
-- device token, invitation, or email-change link issued before this
-- version stops resolving on a SQLite-backed deployment after upgrading,
-- since the app now looks these up by hash and these rows still hold
-- plaintext -- equivalent to a full session flush. Sessions/API keys
-- established after upgrading are unaffected. If this matters for your
-- deployment, migrate to postgres/mysql first, or reissue affected tokens
-- (e.g. ask users to log back in) after upgrading.
SELECT 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1; -- no-op Up has nothing to reverse
-- +goose StatementEnd
