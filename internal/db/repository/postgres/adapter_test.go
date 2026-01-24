package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/internal/db/models"
	"github.com/stephenafamo/bob"
)

func TestPSQLQueryAdapter_UserOperations(t *testing.T) {
	adapter := &PSQLQueryAdapter{}
	ctx := context.Background()
	now := time.Now()

	user := &models.User{
		ID:            "user-123",
		Email:         "test@example.com",
		PasswordHash:  "hash",
		Provider:      "local",
		ProviderID:    nil,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	t.Run("Insert", func(t *testing.T) {
		q := adapter.QueryUserInsert(ctx, user)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		expected := "INSERT INTO \"users\""
		if !strings.Contains(sql, expected) {
			t.Errorf("expected SQL to contain %q, got %q", expected, sql)
		}
		if len(args) < 5 {
			t.Errorf("expected at least 5 args, got %d", len(args))
		}
	})

	t.Run("GetByEmail", func(t *testing.T) {
		q := adapter.QueryUserGetByEmail(ctx, user.Email)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "FROM \"users\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "\"email\" = $1") {
			t.Errorf("expected email condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != user.Email {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		q := adapter.QueryUserGetByID(ctx, user.ID)
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
		q := adapter.QueryUserUpdate(ctx, updateUser)
		sql, _, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "UPDATE \"users\"") {
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
		q := adapter.QueryUserDelete(ctx, user.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "DELETE FROM \"users\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != user.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})
}

func TestPSQLQueryAdapter_TokenOperations(t *testing.T) {
	adapter := &PSQLQueryAdapter{}
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
		q := adapter.QueryTokenInsert(ctx, token)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		expected := "INSERT INTO \"tokens\""
		if !strings.Contains(sql, expected) {
			t.Errorf("expected SQL to contain %q, got %q", expected, sql)
		}
		if len(args) < 5 {
			t.Errorf("expected args, got %d", len(args))
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		q := adapter.QueryTokenGetByID(ctx, token.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "FROM \"tokens\"") {
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
		q := adapter.QueryTokenGetByToken(ctx, token.Token)
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
		q := adapter.QueryTokenDelete(ctx, token.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "DELETE FROM \"tokens\"") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != token.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})
}
