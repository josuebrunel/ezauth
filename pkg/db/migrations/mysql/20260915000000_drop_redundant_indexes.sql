-- +goose Up
-- +goose StatementBegin
-- The init migration defined a UNIQUE constraint (which creates its own
-- index) on each of these columns, then also a separate, identically-
-- scoped explicit index -- two indexes doing the same job, both maintained
-- on every insert/update/delete for no query-performance benefit. Dropping
-- the redundant ones instead of editing the init migration itself: goose
-- doesn't checksum already-applied migration files, so editing history
-- would only change what a brand-new database creates, not the schema any
-- already-deployed one is actually running -- a new migration is the only
-- way to fix that. See #211.
--
-- Unconditional (no existence check, unlike this repo's usual MySQL DDL
-- convention): the init migration always created these three, and MySQL
-- has no IF EXISTS for DROP INDEX, so there's nothing to guard against.
ALTER TABLE ezauth_users DROP INDEX idx_ezauth_users_email;
ALTER TABLE ezauth_users DROP INDEX idx_ezauth_users_provider;
ALTER TABLE ezauth_tokens DROP INDEX idx_ezauth_tokens_token;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users ADD INDEX idx_ezauth_users_email (email);
ALTER TABLE ezauth_users ADD INDEX idx_ezauth_users_provider (provider, provider_id);
ALTER TABLE ezauth_tokens ADD INDEX idx_ezauth_tokens_token (token);
-- +goose StatementEnd
