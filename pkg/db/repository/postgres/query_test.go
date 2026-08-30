package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/stephenafamo/bob"
)

func TestPSQLQuerier_UserOperations(t *testing.T) {
	querier := &PSQLQuerier{}
	ctx := context.Background()
	now := time.Now()

	// Cleanup at the end

	user := &models.User{
		ID:            "user-123",
		Email:         util.UniqueEmail("test"),
		Username:      "testuser",
		PasswordHash:  "hash",
		Provider:      "local",
		ProviderID:    nil,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	t.Run("Insert", func(t *testing.T) {
		q := querier.QueryUserInsert(ctx, user)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		expected := "INSERT INTO \"ezauth_users\""
		if !strings.Contains(sql, expected) {
			t.Errorf("expected SQL to contain %q, got %q", expected, sql)
		}
		if len(args) < 5 {
			t.Errorf("expected at least 5 args, got %d", len(args))
		}
	})

	t.Run("GetByEmail", func(t *testing.T) {
		q := querier.QueryUserGetByEmail(ctx, user.Email)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "FROM \"ezauth_users\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "\"email\" = $1") {
			t.Errorf("expected email condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != user.Email {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("GetByUsername", func(t *testing.T) {
		q := querier.QueryUserGetByUsername(ctx, user.Username)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "FROM \"ezauth_users\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "\"username\" = $1") {
			t.Errorf("expected username condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != user.Username {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		q := querier.QueryUserGetByID(ctx, user.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "\"id\" = $1") {
			t.Errorf("expected id condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != user.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("Update", func(t *testing.T) {
		// Update some fields
		updateUser := &models.User{
			ID:       user.ID,
			Provider: "google",
		}
		q := querier.QueryUserUpdate(ctx, updateUser)
		sql, _, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "UPDATE \"ezauth_users\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		// Check if provider is being updated
		if !strings.Contains(sql, "\"provider\" =") {
			t.Error("expected provider to be updated")
		}
		// Check if id is in where clause
		if !strings.Contains(sql, "\"id\" =") {
			t.Error("expected id in where clause")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		q := querier.QueryUserDelete(ctx, user.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "DELETE FROM \"ezauth_users\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != user.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})
}

func TestPSQLQuerier_TokenOperations(t *testing.T) {
	querier := &PSQLQuerier{}
	ctx := context.Background()
	now := time.Now()

	token := &models.Token{
		ID:        "token-123",
		UserID:    "user-123",
		Token:     "abc-def",
		TokenType: "access",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		Revoked:   false,
	}

	t.Run("Insert", func(t *testing.T) {
		q := querier.QueryTokenInsert(ctx, token)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		expected := "INSERT INTO \"ezauth_tokens\""
		if !strings.Contains(sql, expected) {
			t.Errorf("expected SQL to contain %q, got %q", expected, sql)
		}
		if len(args) < 5 {
			t.Errorf("expected args, got %d", len(args))
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		q := querier.QueryTokenGetByID(ctx, token.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "FROM \"ezauth_tokens\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "\"id\" = $1") {
			t.Errorf("expected id condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != token.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("GetByToken", func(t *testing.T) {
		q := querier.QueryTokenGetByToken(ctx, token.Token)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "\"token\" = $1") {
			t.Errorf("expected token condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != token.Token {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		q := querier.QueryTokenDelete(ctx, token.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "DELETE FROM \"ezauth_tokens\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != token.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})
}

func TestPSQLQuerier_WebauthnCredentialOperations(t *testing.T) {
	querier := &PSQLQuerier{}
	ctx := context.Background()
	now := time.Now()

	cred := &models.WebauthnCredential{
		ID:           "cred-123",
		UserID:       "user-123",
		CredentialID: "raw-credential-id",
		PublicKey:    "base64-public-key",
		SignCount:    0,
		Transports:   "internal,hybrid",
		Name:         "YubiKey 5",
		Data:         models.JSONMap{"id": "raw-credential-id"},
		CreatedAt:    now,
	}

	t.Run("Insert", func(t *testing.T) {
		q := querier.QueryWebauthnCredentialInsert(ctx, cred)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "INSERT") || !strings.Contains(sql, "\"ezauth_webauthn_credentials\"") {
			t.Errorf("expected INSERT INTO ezauth_webauthn_credentials, got %q", sql)
		}
		if len(args) < 5 {
			t.Errorf("expected args, got %d", len(args))
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		q := querier.QueryWebauthnCredentialGetByID(ctx, cred.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "\"id\" = $1") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != cred.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("GetByCredentialID", func(t *testing.T) {
		q := querier.QueryWebauthnCredentialGetByCredentialID(ctx, cred.CredentialID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "credential_id") {
			t.Errorf("expected credential_id condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != cred.CredentialID {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("ListByUserID", func(t *testing.T) {
		q := querier.QueryWebauthnCredentialListByUserID(ctx, cred.UserID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "user_id") {
			t.Errorf("expected user_id condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != cred.UserID {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("Update", func(t *testing.T) {
		updated := *cred
		updated.SignCount = 5
		q := querier.QueryWebauthnCredentialUpdate(ctx, &updated)
		sql, _, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "UPDATE") || !strings.Contains(sql, "\"ezauth_webauthn_credentials\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "sign_count") {
			t.Error("expected sign_count to be updated")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		q := querier.QueryWebauthnCredentialDelete(ctx, cred.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "DELETE FROM \"ezauth_webauthn_credentials\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != cred.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})
}
