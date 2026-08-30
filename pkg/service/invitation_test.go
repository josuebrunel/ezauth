package service

import (
	"context"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func setupInvitationTestDB(t *testing.T) *Auth {
	dialect, dsn := util.GetTestDBConfig("invitation_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		EmailTemplates: config.EmailTemplates{
			InvitationSubject: "You've been invited",
			InvitationBody:    "Click the following link to accept your invitation: {{.Link}}",
		},
		Invitation: config.Invitation{TTL: 168 * time.Hour},
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := migrations.MigrateUpWithDBConn(auth.Repo.DB(), dialect); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func TestInvitationFlow(t *testing.T) {
	auth := setupInvitationTestDB(t)
	ctx := context.Background()

	inviter, err := auth.Repo.UserCreate(ctx, &models.User{
		Email:    util.UniqueEmail("inviter"),
		Provider: "local",
	})
	if err != nil {
		t.Fatalf("failed to create inviter: %v", err)
	}

	inviteeEmail := util.UniqueEmail("invitee")

	var invitationID string
	t.Run("create sends an email and returns invitation info", func(t *testing.T) {
		info, err := auth.InvitationCreate(ctx, inviter, RequestInvitation{
			Email: inviteeEmail,
			Roles: "member",
			Data:  map[string]any{"org_id": "org-123"},
		})
		if err != nil {
			t.Fatalf("InvitationCreate failed: %v", err)
		}
		if info.Email != inviteeEmail || info.Roles != "member" {
			t.Fatalf("unexpected invitation info: %+v", info)
		}
		invitationID = info.ID

		mockMailer := auth.Mailer.(*MockMailer)
		if len(mockMailer.SentEmails) != 1 {
			t.Fatalf("expected 1 email sent, got %d", len(mockMailer.SentEmails))
		}
	})

	t.Run("rejects inviting an already-registered email", func(t *testing.T) {
		if _, err := auth.InvitationCreate(ctx, inviter, RequestInvitation{Email: inviter.Email}); err != ErrEmailAlreadyRegistered {
			t.Fatalf("expected ErrEmailAlreadyRegistered, got %v", err)
		}
	})

	t.Run("shows up in Invitations", func(t *testing.T) {
		invitations, err := auth.Invitations(ctx, inviter.ID)
		if err != nil {
			t.Fatalf("Invitations failed: %v", err)
		}
		if len(invitations) != 1 || invitations[0].ID != invitationID {
			t.Fatalf("unexpected invitations: %+v", invitations)
		}
	})

	mockMailer := auth.Mailer.(*MockMailer)
	sentBody := mockMailer.SentEmails[0]["body"]
	tokenValue := sentBody[len(sentBody)-64:]

	t.Run("preview returns invitation details without consuming it", func(t *testing.T) {
		info, err := auth.InvitationPreview(ctx, tokenValue)
		if err != nil {
			t.Fatalf("InvitationPreview failed: %v", err)
		}
		if info.Email != inviteeEmail || info.Roles != "member" {
			t.Fatalf("unexpected preview: %+v", info)
		}
	})

	t.Run("accept rejects a mismatched/unknown token", func(t *testing.T) {
		if _, _, err := auth.InvitationAccept(ctx, RequestInvitationAccept{Token: "not-a-real-token", Password: "securepass123"}); err != ErrInvalidOrExpiredInvitation {
			t.Fatalf("expected ErrInvalidOrExpiredInvitation, got %v", err)
		}
	})

	t.Run("accept creates a pre-verified account with the invited roles", func(t *testing.T) {
		user, tokens, err := auth.InvitationAccept(ctx, RequestInvitationAccept{
			Token:    tokenValue,
			Password: "securepass123",
			Username: "inviteduser",
		})
		if err != nil {
			t.Fatalf("InvitationAccept failed: %v", err)
		}
		if user.Email != inviteeEmail || !user.EmailVerified || user.Roles != "member" {
			t.Fatalf("unexpected user: %+v", user)
		}
		if tokens.AccessToken == "" {
			t.Fatal("expected access token")
		}
		if got, ok := models.GetMeta[string](user, "org_id"); !ok || got != "org-123" {
			t.Fatalf("expected org_id metadata to carry through, got %q ok=%v", got, ok)
		}
	})

	t.Run("invitation is single-use", func(t *testing.T) {
		if _, _, err := auth.InvitationAccept(ctx, RequestInvitationAccept{Token: tokenValue, Password: "securepass123"}); err != ErrInvalidOrExpiredInvitation {
			t.Fatalf("expected reused invitation to be rejected, got %v", err)
		}
	})

	t.Run("revoke rejects another user's invitation", func(t *testing.T) {
		other, err := auth.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("other"), Provider: "local"})
		if err != nil {
			t.Fatalf("failed to create other user: %v", err)
		}
		info, err := auth.InvitationCreate(ctx, inviter, RequestInvitation{Email: util.UniqueEmail("invitee2")})
		if err != nil {
			t.Fatalf("InvitationCreate failed: %v", err)
		}
		if err := auth.InvitationRevoke(ctx, other, info.ID); err != ErrInvitationNotFound {
			t.Fatalf("expected ErrInvitationNotFound, got %v", err)
		}
		if err := auth.InvitationRevoke(ctx, inviter, info.ID); err != nil {
			t.Fatalf("InvitationRevoke by the actual inviter failed: %v", err)
		}
	})
}
