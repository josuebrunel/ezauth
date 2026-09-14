-- +goose Up
-- +goose StatementBegin
-- avatar_url is already TEXT (unbounded) on postgres, but locale/timezone
-- were VARCHAR(50)/VARCHAR(100) -- narrower than mysql's original
-- VARCHAR(10)/VARCHAR(50) in one sense, but still a fixed bound, and
-- different from mysql's (also being fixed in this same migration set), so
-- the same application code could still behave differently depending on
-- the deployed dialect. Widen both to TEXT for parity across all three.
ALTER TABLE ezauth_users ALTER COLUMN locale TYPE TEXT;
ALTER TABLE ezauth_users ALTER COLUMN timezone TYPE TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE ezauth_users ALTER COLUMN locale TYPE VARCHAR(50);
ALTER TABLE ezauth_users ALTER COLUMN timezone TYPE VARCHAR(100);
-- +goose StatementEnd
