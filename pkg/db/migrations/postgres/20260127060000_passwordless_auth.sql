-- +goose Up
-- +goose StatementBegin
CREATE TABLE passwordless_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_passwordless_email ON passwordless_tokens(email);
CREATE INDEX idx_passwordless_token ON passwordless_tokens(token);
CREATE INDEX idx_passwordless_expires_at ON passwordless_tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS passwordless_tokens;
-- +goose StatementEnd
