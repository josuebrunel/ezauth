package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

// failingMailer is a Mailer whose delivery always fails.
type failingMailer struct{}

func (failingMailer) Send(string, string, string) error { return errors.New("smtp is down") }

func invitationInviter(t *testing.T, auth *Auth) *models.User {
	t.Helper()
	u, err := auth.Repo.UserCreate(context.Background(), &models.User{Email: util.UniqueEmail("inviter"), Provider: "local"})
	if err != nil {
		t.Fatalf("failed to create inviter: %v", err)
	}
	return u
}

// tokenFromLink pulls the raw token out of an accept link.
func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "token=")
	if !ok || token == "" {
		t.Fatalf("no token in link %q", link)
	}
	return token
}

// listAllInvitations pages through every open invitation.
func listAllInvitations(t *testing.T, auth *Auth) []InvitationInfo {
	t.Helper()
	var all []InvitationInfo
	for offset := 0; ; offset += 100 {
		res, err := auth.InvitationsAll(context.Background(), ListInvitationsOptions{Limit: 100, Offset: offset})
		if err != nil {
			t.Fatalf("InvitationsAll failed: %v", err)
		}
		all = append(all, res.Invitations...)
		if !res.HasMore {
			return all
		}
	}
}

func findInvitation(list []InvitationInfo, email string) *InvitationInfo {
	for i := range list {
		if list[i].Email == email {
			return &list[i]
		}
	}
	return nil
}

// InvitationCreate only emailed the link, so with no mail delivery nobody could
// get it, and a failed send left an open invitation nobody had the link to.
// See #223.
func TestInvitationIssue(t *testing.T) {
	ctx := context.Background()
	auth := setupInvitationTestDB(t)
	inviter := invitationInviter(t, auth)

	t.Run("returns the link, which accepts the invitation", func(t *testing.T) {
		email := util.UniqueEmail("invitee")
		issued, err := auth.InvitationIssue(ctx, inviter, RequestInvitation{Email: email})
		if err != nil {
			t.Fatalf("InvitationIssue failed: %v", err)
		}
		if issued.EmailErr != nil {
			t.Errorf("unexpected EmailErr: %v", issued.EmailErr)
		}
		if issued.Email != email || issued.InviterID != inviter.ID {
			t.Errorf("unexpected invitation: %+v", issued.InvitationInfo)
		}
		if !strings.Contains(issued.Link, "/invitation/accept?token=") {
			t.Errorf("link %q is not an accept link", issued.Link)
		}

		mock := auth.Mailer.(*MockMailer)
		last := mock.SentEmails[len(mock.SentEmails)-1]
		if last["to"] != email || !strings.Contains(last["body"], issued.Link) {
			t.Errorf("the email did not carry the link: %v", last)
		}

		preview, err := auth.InvitationPreview(ctx, tokenFromLink(t, issued.Link))
		if err != nil {
			t.Fatalf("the returned link does not work: %v", err)
		}
		if preview.ID != issued.ID {
			t.Errorf("link opens invitation %s, want %s", preview.ID, issued.ID)
		}
	})

	t.Run("the link never reaches JSON", func(t *testing.T) {
		issued, err := auth.InvitationIssue(ctx, inviter, RequestInvitation{Email: util.UniqueEmail("invitee")})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(issued)
		if err != nil {
			t.Fatal(err)
		}
		token := tokenFromLink(t, issued.Link)
		if strings.Contains(string(raw), token) || strings.Contains(strings.ToLower(string(raw)), "link") {
			t.Errorf("the link leaked into JSON: %s", raw)
		}
	})

	t.Run("a mail failure is reported and the invitation stays", func(t *testing.T) {
		prev := auth.Mailer
		auth.Mailer = failingMailer{}
		defer func() { auth.Mailer = prev }()

		email := util.UniqueEmail("invitee")
		issued, err := auth.InvitationIssue(ctx, inviter, RequestInvitation{Email: email})
		if err != nil {
			t.Fatalf("InvitationIssue should not fail when only the email does: %v", err)
		}
		if issued.EmailErr == nil {
			t.Error("EmailErr is nil although the mailer failed")
		}
		if issued.Link == "" {
			t.Error("no link to share when the email failed")
		}
		if _, err := auth.InvitationPreview(ctx, tokenFromLink(t, issued.Link)); err != nil {
			t.Errorf("the invitation is not usable: %v", err)
		}
	})

	t.Run("InvitationCreate fails and leaves no open invitation when mail fails", func(t *testing.T) {
		prev := auth.Mailer
		auth.Mailer = failingMailer{}
		defer func() { auth.Mailer = prev }()

		email := util.UniqueEmail("invitee")
		if _, err := auth.InvitationCreate(ctx, inviter, RequestInvitation{Email: email}); err == nil {
			t.Fatal("InvitationCreate succeeded although the email failed")
		}
		open, err := auth.Invitations(ctx, inviter.ID)
		if err != nil {
			t.Fatal(err)
		}
		if findInvitation(open, email) != nil {
			t.Error("a failed send left an open invitation behind")
		}
	})

	t.Run("keeps the existing rules", func(t *testing.T) {
		existing := invitationInviter(t, auth)
		if _, err := auth.InvitationIssue(ctx, inviter, RequestInvitation{Email: existing.Email}); !errors.Is(err, ErrEmailAlreadyRegistered) {
			t.Errorf("an existing account: got %v, want ErrEmailAlreadyRegistered", err)
		}
		if _, err := auth.InvitationIssue(ctx, inviter, RequestInvitation{Email: util.UniqueEmail("x"), Roles: "never-held-" + uniqueName("r")}); !errors.Is(err, ErrCannotGrantRole) {
			t.Errorf("a role the inviter lacks: got %v, want ErrCannotGrantRole", err)
		}
		if _, err := auth.InvitationIssue(ctx, inviter, RequestInvitation{Email: "not an email"}); err == nil {
			t.Error("an invalid email was accepted")
		}
	})
}

// Invitations(inviterID) shows one inviter's invitations, which is no use to an
// admin who needs to see them all. See #224.
func TestInvitationsAll(t *testing.T) {
	ctx := context.Background()
	auth := setupInvitationTestDB(t)
	a, b := invitationInviter(t, auth), invitationInviter(t, auth)

	issue := func(inviter *models.User) (string, *IssuedInvitation) {
		t.Helper()
		email := util.UniqueEmail("invitee")
		issued, err := auth.InvitationIssue(ctx, inviter, RequestInvitation{Email: email})
		if err != nil {
			t.Fatalf("InvitationIssue failed: %v", err)
		}
		return email, issued
	}
	emailA1, a1 := issue(a)
	emailB1, b1 := issue(b)
	// An invitation that is already expired when it is created.
	prevTTL := auth.Cfg.Invitation.TTL
	auth.Cfg.Invitation.TTL = -time.Hour
	emailA2, a2 := issue(a)
	auth.Cfg.Invitation.TTL = prevTTL

	t.Run("lists every inviter's invitations, newest first", func(t *testing.T) {
		all := listAllInvitations(t, auth)
		var ours []InvitationInfo
		for _, inv := range all {
			switch inv.Email {
			case emailA1, emailB1, emailA2:
				ours = append(ours, inv)
			}
		}
		if len(ours) != 3 {
			t.Fatalf("found %d of the 3 invitations", len(ours))
		}
		// Never out of order by creation time. (MySQL stores whole seconds, so
		// invitations created in the same second tie and fall back to their ids.)
		for i := 1; i < len(ours); i++ {
			if ours[i].CreatedAt.After(ours[i-1].CreatedAt) {
				t.Errorf("not newest first: %s is listed before %s", ours[i-1].CreatedAt, ours[i].CreatedAt)
			}
		}
		if got := findInvitation(all, emailB1); got == nil || got.InviterID != b.ID || got.ID != b1.ID {
			t.Errorf("invitation from b: %+v", got)
		}
		if got := findInvitation(all, emailA1); got == nil || got.InviterID != a.ID {
			t.Errorf("invitation from a: %+v", got)
		}
	})

	t.Run("expired invitations stay listed, so they can be re-issued", func(t *testing.T) {
		got := findInvitation(listAllInvitations(t, auth), emailA2)
		if got == nil {
			t.Fatal("the expired invitation is missing")
		}
		if !got.ExpiresAt.Before(time.Now()) {
			t.Errorf("ExpiresAt %s should be in the past", got.ExpiresAt)
		}
		_ = a2
	})

	t.Run("pages with HasMore", func(t *testing.T) {
		p1, err := auth.InvitationsAll(ctx, ListInvitationsOptions{Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(p1.Invitations) != 1 || !p1.HasMore {
			t.Fatalf("page 1: %d invitations, more=%t; want 1 and more", len(p1.Invitations), p1.HasMore)
		}
		p2, err := auth.InvitationsAll(ctx, ListInvitationsOptions{Limit: 1, Offset: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(p2.Invitations) != 1 || p2.Invitations[0].ID == p1.Invitations[0].ID {
			t.Errorf("page 2 repeats page 1: %+v", p2.Invitations)
		}
	})

	t.Run("revoked and accepted invitations are gone", func(t *testing.T) {
		if err := auth.InvitationRevoke(ctx, b, b1.ID); err != nil {
			t.Fatal(err)
		}
		if _, _, err := auth.InvitationAccept(ctx, RequestInvitationAccept{Token: tokenFromLink(t, a1.Link), Password: "correct-horse-battery-staple"}); err != nil {
			t.Fatalf("InvitationAccept failed: %v", err)
		}
		all := listAllInvitations(t, auth)
		if findInvitation(all, emailB1) != nil {
			t.Error("a revoked invitation is still listed")
		}
		if findInvitation(all, emailA1) != nil {
			t.Error("an accepted invitation is still listed")
		}
		if findInvitation(all, emailA2) == nil {
			t.Error("an untouched invitation disappeared")
		}
	})
}

// InvitationRevoke only works for the inviter who sent it. See #225.
func TestInvitationRevokeByID(t *testing.T) {
	ctx := context.Background()
	auth := setupInvitationTestDB(t)
	sender, other := invitationInviter(t, auth), invitationInviter(t, auth)

	issued, err := auth.InvitationIssue(ctx, sender, RequestInvitation{Email: util.UniqueEmail("invitee")})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("InvitationRevoke still checks ownership", func(t *testing.T) {
		if err := auth.InvitationRevoke(ctx, other, issued.ID); !errors.Is(err, ErrInvitationNotFound) {
			t.Fatalf("got %v, want ErrInvitationNotFound", err)
		}
		if _, err := auth.InvitationPreview(ctx, tokenFromLink(t, issued.Link)); err != nil {
			t.Errorf("a refused revoke still revoked: %v", err)
		}
	})

	t.Run("revokes any invitation, and its link stops working", func(t *testing.T) {
		if err := auth.InvitationRevokeByID(ctx, issued.ID); err != nil {
			t.Fatalf("InvitationRevokeByID failed: %v", err)
		}
		_, _, err := auth.InvitationAccept(ctx, RequestInvitationAccept{Token: tokenFromLink(t, issued.Link), Password: "correct-horse-battery-staple"})
		if !errors.Is(err, ErrInvalidOrExpiredInvitation) {
			t.Errorf("accepting a revoked invitation: got %v, want ErrInvalidOrExpiredInvitation", err)
		}
	})

	t.Run("unknown ids and other kinds of token are refused", func(t *testing.T) {
		if err := auth.InvitationRevokeByID(ctx, util.NewIDStripped()); !errors.Is(err, ErrInvitationNotFound) {
			t.Errorf("unknown id: got %v, want ErrInvitationNotFound", err)
		}
		if _, err := auth.TokenCreate(ctx, other); err != nil {
			t.Fatal(err)
		}
		toks, err := auth.Repo.TokenListByUserID(ctx, other.ID, 5)
		if err != nil || len(toks) == 0 {
			t.Fatalf("no tokens to test with: %v", err)
		}
		if err := auth.InvitationRevokeByID(ctx, toks[0].ID); !errors.Is(err, ErrInvitationNotFound) {
			t.Errorf("a session token: got %v, want ErrInvitationNotFound", err)
		}
		still, err := auth.Repo.TokenGetByID(ctx, toks[0].ID)
		if err != nil || still.Revoked {
			t.Errorf("the session token was revoked through the invitation method (err=%v)", err)
		}
	})
}
