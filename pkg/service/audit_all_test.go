package service

import (
	"context"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// AuditLogsAll lists events across users. Tests tag their rows with a unique
// event type so a persistent test database full of other rows doesn't matter.
func TestAuditLogsAll(t *testing.T) {
	ctx := context.Background()
	auth := setupAuditTestDB(t, 5, time.Hour)

	userA := auditTestUser(t, auth, ctx)
	userB := auditTestUser(t, auth, ctx)
	typ := uniqueName("test.event.")
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	record := func(userID *string, at time.Time, meta models.JSONMap) {
		t.Helper()
		if _, err := auth.Repo.AuditLogCreate(ctx, &models.AuditLog{UserID: userID, EventType: typ, Metadata: meta, CreatedAt: at}); err != nil {
			t.Fatalf("AuditLogCreate failed: %v", err)
		}
	}
	record(&userA.ID, base.Add(1*time.Minute), models.JSONMap{"n": "first"})
	record(&userB.ID, base.Add(2*time.Minute), models.JSONMap{"n": "second"})
	record(&userA.ID, base.Add(3*time.Minute), models.JSONMap{"n": "third"})

	t.Run("lists newest first with the user's email", func(t *testing.T) {
		res, err := auth.AuditLogsAll(ctx, ListAuditLogsOptions{EventType: typ})
		if err != nil {
			t.Fatalf("AuditLogsAll failed: %v", err)
		}
		if len(res.Events) != 3 || res.HasMore {
			t.Fatalf("expected 3 events and no more, got %d (more=%t)", len(res.Events), res.HasMore)
		}
		wantOrder := []string{"third", "second", "first"}
		wantEmail := []string{userA.Email, userB.Email, userA.Email}
		for i, e := range res.Events {
			if got, _ := e.Metadata["n"].(string); got != wantOrder[i] {
				t.Errorf("event %d: metadata n = %q, want %q (not newest first)", i, got, wantOrder[i])
			}
			if e.UserEmail == nil || *e.UserEmail != wantEmail[i] {
				t.Errorf("event %d: user email = %v, want %q", i, e.UserEmail, wantEmail[i])
			}
			if e.UserID == nil {
				t.Errorf("event %d: user id is nil", i)
			}
		}
	})

	t.Run("pages with HasMore", func(t *testing.T) {
		p1, err := auth.AuditLogsAll(ctx, ListAuditLogsOptions{EventType: typ, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(p1.Events) != 2 || !p1.HasMore {
			t.Fatalf("page 1: got %d events, more=%t; want 2 and more", len(p1.Events), p1.HasMore)
		}
		p2, err := auth.AuditLogsAll(ctx, ListAuditLogsOptions{EventType: typ, Limit: 2, Offset: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(p2.Events) != 1 || p2.HasMore {
			t.Fatalf("page 2: got %d events, more=%t; want 1 and no more", len(p2.Events), p2.HasMore)
		}
		if p2.Events[0].ID == p1.Events[0].ID || p2.Events[0].ID == p1.Events[1].ID {
			t.Error("page 2 repeats an event from page 1")
		}
	})

	t.Run("filters by time window", func(t *testing.T) {
		since, until := base.Add(90*time.Second), base.Add(150*time.Second)
		res, err := auth.AuditLogsAll(ctx, ListAuditLogsOptions{EventType: typ, Since: &since, Until: &until})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 1 {
			t.Fatalf("expected only the event at +2m, got %d", len(res.Events))
		}
		if got, _ := res.Events[0].Metadata["n"].(string); got != "second" {
			t.Errorf("got event %q, want second", got)
		}
	})

	t.Run("an unknown event type matches nothing", func(t *testing.T) {
		res, err := auth.AuditLogsAll(ctx, ListAuditLogsOptions{EventType: uniqueName("never.")})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 0 || res.HasMore {
			t.Errorf("expected nothing, got %d events", len(res.Events))
		}
	})

	t.Run("events of a deleted user stay listed, without a user", func(t *testing.T) {
		if err := auth.Repo.UserDelete(ctx, userB.ID); err != nil {
			t.Fatalf("UserDelete failed: %v", err)
		}
		res, err := auth.AuditLogsAll(ctx, ListAuditLogsOptions{EventType: typ})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 3 {
			t.Fatalf("expected the 3 events to survive, got %d", len(res.Events))
		}
		orphans := 0
		for _, e := range res.Events {
			if e.UserID == nil {
				orphans++
				if e.UserEmail != nil {
					t.Errorf("an event with no user still has an email: %q", *e.UserEmail)
				}
			}
		}
		if orphans != 1 {
			t.Errorf("expected exactly 1 event without a user, got %d", orphans)
		}
	})
}
