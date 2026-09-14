-- +goose Up
-- +goose StatementBegin
-- Normalize existing username casing to lowercase. New rows are already
-- normalized at write time (see Repository.UserCreate/UserUpdate/
-- UserGetByUsername) -- this backfills data written before that change, so
-- the unique index below compares consistently.
UPDATE ezauth_users
SET username = LOWER(username)
WHERE username <> '' AND username <> LOWER(username);

-- Resolve any usernames left colliding after normalization -- including
-- pre-existing exact duplicates, possible before this index existed, since
-- nothing enforced uniqueness on this column until now. Keep the
-- lowest-id row untouched and suffix every other row sharing that username
-- with its own id (guaranteed unique, unlike a truncated substring), so the
-- unique index below can't fail to create.
UPDATE ezauth_users
SET username = username || '_' || id::text
WHERE username <> ''
  AND EXISTS (
    SELECT 1 FROM ezauth_users u2
    WHERE u2.username = ezauth_users.username
      AND u2.id <> ezauth_users.id
      AND u2.id < ezauth_users.id
  );

-- Partial unique index: multiple users may have an empty username ('' default),
-- but no two users may share the same non-empty username.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ezauth_users_username_unique ON ezauth_users(username) WHERE username <> '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_ezauth_users_username_unique;
-- +goose StatementEnd
