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
DROP INDEX IF EXISTS idx_ezauth_users_email;
DROP INDEX IF EXISTS idx_ezauth_users_provider;
DROP INDEX IF EXISTS idx_ezauth_tokens_token;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS idx_ezauth_users_email ON ezauth_users(email);
CREATE INDEX IF NOT EXISTS idx_ezauth_users_provider ON ezauth_users(provider, provider_id);
CREATE INDEX IF NOT EXISTS idx_ezauth_tokens_token ON ezauth_tokens(token);
-- +goose StatementEnd
