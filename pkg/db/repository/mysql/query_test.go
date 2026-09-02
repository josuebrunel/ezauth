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

	t.Run("GetByUsername", func(t *testing.T) {
		q := querier.QueryUserGetByUsername(ctx, user.Username)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}

		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "ezauth_users") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "username") {
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

func TestMysqlQuerier_WebauthnCredentialOperations(t *testing.T) {
	querier := &MysqlQuerier{}
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
		if !strings.Contains(sql, "INSERT") || !strings.Contains(sql, "ezauth_webauthn_credentials") {
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
		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "ezauth_webauthn_credentials") {
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
		if !strings.Contains(sql, "UPDATE") || !strings.Contains(sql, "ezauth_webauthn_credentials") {
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
		if !strings.Contains(sql, "DELETE FROM") || !strings.Contains(sql, "ezauth_webauthn_credentials") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if len(args) != 1 || args[0] != cred.ID {
			t.Errorf("unexpected args: %v", args)
		}
	})
}

func TestMysqlQuerier_AuditLogOperations(t *testing.T) {
	querier := &MysqlQuerier{}
	ctx := context.Background()

	log := &models.AuditLog{
		UserID:    "user-123",
		EventType: models.AuditEventLoginSucceeded,
	}

	t.Run("Insert", func(t *testing.T) {
		q := querier.QueryAuditLogInsert(ctx, log)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "INSERT") || !strings.Contains(sql, "ezauth_audit_logs") {
			t.Errorf("expected INSERT INTO ezauth_audit_logs, got %q", sql)
		}
		if len(args) < 3 {
			t.Errorf("expected at least 3 args, got %d", len(args))
		}
		if log.ID == "" {
			t.Error("expected ID to be generated")
		}
	})

	t.Run("ListByUserID", func(t *testing.T) {
		q := querier.QueryAuditLogListByUserID(ctx, log.UserID, models.AuditLogFilter{}, 20, 0)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "SELECT") || !strings.Contains(sql, "ezauth_audit_logs") {
			t.Errorf("unexpected SQL: %s", sql)
		}
		if !strings.Contains(sql, "user_id") {
			t.Errorf("expected user_id condition, got %s", sql)
		}
		if len(args) != 1 || args[0] != log.UserID {
			t.Errorf("unexpected args: %v", args)
		}
	})

	t.Run("ListByUserID with filters", func(t *testing.T) {
		since := time.Now().Add(-24 * time.Hour)
		until := time.Now()
		filter := models.AuditLogFilter{EventType: models.AuditEventLoginFailed, Since: &since, Until: &until}
		q := querier.QueryAuditLogListByUserID(ctx, log.UserID, filter, 20, 0)
		sql, args, err := bob.Build(ctx, q)
		if err != nil {
			t.Fatalf("failed to build query: %v", err)
		}
		if !strings.Contains(sql, "event_type") {
			t.Errorf("expected event_type condition, got %s", sql)
		}
		if len(args) != 4 {
			t.Errorf("expected 4 args (user_id, event_type, since, until), got %d", len(args))
		}
	})
}
