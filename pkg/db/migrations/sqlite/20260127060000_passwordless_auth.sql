-- +goose Up
-- +goose StatementBegin
CREATE TABLE passwordless_tokens (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    email TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_passwordless_email ON passwordless_tokens(email);
CREATE INDEX idx_passwordless_token ON passwordless_tokens(token);
CREATE INDEX idx_passwordless_expires_at ON passwordless_tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS passwordless_tokens;
-- +goose StatementEnd
