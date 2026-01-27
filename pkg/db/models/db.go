package models

const (
	TableUser             = "users"
	TableToken            = "tokens"
	TablePasswordlessToken = "passwordless_tokens"
	ColumnEmail           = "email"
	ColumnPasswordHash  = "password_hash"
	ColumnProvider      = "provider"
	ColumnProviderID    = "provider_id"
	ColumnEmailVerified = "email_verified"
	ColumnAppMetadata   = "app_metadata"
	ColumnUserMetadata  = "user_metadata"
	ColumnCreatedAt     = "created_at"
	ColumnUpdatedAt     = "updated_at"
	ColumnUserID        = "user_id"
	ColumnToken         = "token"
	ColumnTokenType     = "token_type"
	ColumnExpiresAt     = "expires_at"
	ColumnRevoked       = "revoked"
	ColumnMetadata      = "metadata"
)
