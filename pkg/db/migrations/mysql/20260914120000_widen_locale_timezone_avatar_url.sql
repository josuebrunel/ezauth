-- +goose Up
-- +goose StatementBegin
-- Widen locale/timezone/avatar_url to TEXT, matching postgres/sqlite (which
-- have never had a cap on these columns). A value accepted when writing
-- against postgres/sqlite could be rejected here by MySQL's stricter
-- VARCHAR(10)/VARCHAR(50)/VARCHAR(500) widths, so the same application code
-- behaved differently depending on the deployed dialect.
-- TEXT/BLOB columns in MySQL reject a plain literal DEFAULT ('' here) --
-- only the 8.0.13+ expression-default form (DEFAULT ('')) is accepted.
ALTER TABLE ezauth_users MODIFY COLUMN locale TEXT DEFAULT ('');
ALTER TABLE ezauth_users MODIFY COLUMN timezone TEXT DEFAULT ('');
ALTER TABLE ezauth_users MODIFY COLUMN avatar_url TEXT DEFAULT ('');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users MODIFY COLUMN locale VARCHAR(10) DEFAULT '';
ALTER TABLE ezauth_users MODIFY COLUMN timezone VARCHAR(50) DEFAULT '';
ALTER TABLE ezauth_users MODIFY COLUMN avatar_url VARCHAR(500) DEFAULT '';
-- +goose StatementEnd
