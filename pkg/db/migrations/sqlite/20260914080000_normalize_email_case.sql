-- +goose Up
-- +goose StatementBegin
-- Normalize existing email casing to lowercase. New rows are already
-- normalized at write time (see Repository.UserCreate/UserUpdate/
-- UserGetByEmail) -- this backfills data written before that change.
-- Postgres/sqlite compare email case-sensitively by default (unlike mysql's
-- default collation), so two accounts differing only by case were both
-- possible to create and treated as distinct. Skip any row that would
-- collide with another user's email case-insensitively, since forcing that
-- would violate the UNIQUE constraint; such pairs (if any exist) need
-- manual resolution by an operator.
UPDATE ezauth_users
SET email = LOWER(email)
WHERE email <> LOWER(email)
  AND NOT EXISTS (
    SELECT 1 FROM ezauth_users u2
    WHERE u2.id <> ezauth_users.id AND LOWER(u2.email) = LOWER(ezauth_users.email)
  );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1; -- original casing can't be recovered; intentional no-op
-- +goose StatementEnd
