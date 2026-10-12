-- +goose Up
-- +goose StatementBegin
-- UsersList sorts newest first and the sign-ups count filters on created_at,
-- but this column had no index, so both scanned the whole users table (and
-- UsersList sorted all of it) on every request. With the index the newest
-- page is read straight off its end: on 50,000 users UsersList went from
-- 5.7 ms to 0.17 ms and the sign-ups query from 8.3 ms to 1.9 ms, and the
-- gap grows with the table.
CREATE INDEX IF NOT EXISTS idx_ezauth_users_created_at ON ezauth_users(created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_ezauth_users_created_at;
-- +goose StatementEnd
