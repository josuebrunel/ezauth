package mysql

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/stephenafamo/bob"
)

func TestMysqlQuerier_UserOperations(t *testing.T) {
	querier := &MysqlQuerier{}
	ctx := context.Background()
	now := time.Now()

	user := &models.User{
		ID:            "user-123",
		Email:         util.UniqueEmail("test"),
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

		if !strings.Contains(sql, "INSERT") || !strings.Contains(sql, "ezauth_users") {
			t.Errorf("expected INSERT INTO ezauth_users, got %q", sql)
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

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "ezauth_users") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "email") {
			t.Errorf("expected email condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != user.Email {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("GetByID", func(t *testing.T) {
		q := querier.QueryUserGetByID(ctx, user.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "id") {
			t.Errorf("expected id condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != user.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("Update", func(t *testing.T) {
		updateUser := &models.User{
			ID:       user.ID,
			Provider: "google",
		}
		q := querier.QueryUserUpdate(ctx, updateUser)
		sql, _, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "UPDATE") || !strings.Contains(sql, "ezauth_users") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "provider") {
			t.Error("expected provider to be updated")
		}
		if !strings.Contains(sql, "id") {
			t.Error("expected id in where clause")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		q := querier.QueryUserDelete(ctx, user.ID)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "DELETE FROM") || !strings.Contains(sql, "ezauth_users") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != user.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})
}

func TestMysqlQuerier_TokenOperations(t *testing.T) {
	querier := &MysqlQuerier{}
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

		if !strings.Contains(sql, "INSERT") || !strings.Contains(sql, "ezauth_tokens") {
			t.Errorf("expected INSERT INTO ezauth_tokens, got %q", sql)
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

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "ezauth_tokens") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "id") {
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

		if !strings.Contains(sql, "token") {
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

		if !strings.Contains(sql, "DELETE FROM") || !strings.Contains(sql, "ezauth_tokens") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != token.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})

}
