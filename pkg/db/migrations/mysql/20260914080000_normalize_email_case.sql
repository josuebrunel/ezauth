-- +goose Up
-- +goose StatementBegin
-- Normalize existing email casing to lowercase. New rows are already
-- normalized at write time (see Repository.UserCreate/UserUpdate/
-- UserGetByEmail) -- this backfills data written before that change.
-- mysql's default collation is already case-insensitive, so a colliding
-- pair can't exist here the way it can on postgres/sqlite; this is a
-- straightforward cosmetic normalization on mysql, included for parity so
-- ezauth_users.email reads the same way regardless of backend.
UPDATE ezauth_users
SET email = LOWER(email)
WHERE email <> LOWER(email);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1; -- original casing can't be recovered; intentional no-op
-- +goose StatementEnd
