-- +goose Up
-- +goose StatementBegin
-- No-op here: locale/timezone/avatar_url are already TEXT (unbounded) on
-- sqlite. Kept in step with the matching mysql migration, which widens
-- those columns from a fixed VARCHAR width to TEXT for parity across
-- dialects.
SELECT 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
