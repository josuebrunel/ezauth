package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func ptr(s string) *string { return &s }

// uniquePhone returns a valid phone number no other test is using, since
// phones are unique and a persistent test database keeps earlier rows.
func uniquePhone() string {
	return fmt.Sprintf("+1%010d", time.Now().UnixNano()%10_000_000_000)
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

func profileTestUser(t *testing.T, auth *Auth) *models.User {
	t.Helper()
	u, err := auth.UserCreate(context.Background(), &RequestBasicAuth{
		Email:     util.UniqueEmail("profile"),
		Password:  "correct-horse-battery-staple",
		FirstName: "Alice",
		LastName:  "Martin",
		Username:  uniqueName("alice"),
		Phone:     uniquePhone(),
		Locale:    "fr",
		Timezone:  "Europe/Paris",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// UserUpdate skips empty values, so it can never clear a field. See #216.
func TestUserProfileUpdate(t *testing.T) {
	ctx := context.Background()
	auth := setupTestDB(t)

	t.Run("clears a field with a pointer to the empty string", func(t *testing.T) {
		u := profileTestUser(t, auth)
		got, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{FirstName: ptr(""), Phone: ptr("")})
		if err != nil {
			t.Fatalf("UserProfileUpdate failed: %v", err)
		}
		if got.FirstName != "" || got.Phone != "" {
			t.Errorf("expected first name and phone cleared, got %q and %q", got.FirstName, got.Phone)
		}
		if got.LastName != "Martin" || got.Locale != "fr" || got.Timezone != "Europe/Paris" || got.Username != u.Username {
			t.Errorf("fields that weren't mentioned changed: %+v", got)
		}
		// And it really is stored, not just returned.
		stored, err := auth.Repo.UserGetByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.FirstName != "" || stored.Phone != "" {
			t.Errorf("stored first name and phone not cleared: %q %q", stored.FirstName, stored.Phone)
		}
	})

	t.Run("sets some fields and leaves nil ones alone", func(t *testing.T) {
		u := profileTestUser(t, auth)
		got, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{FirstName: ptr("  Alicia "), Timezone: ptr("Asia/Tokyo")})
		if err != nil {
			t.Fatal(err)
		}
		if got.FirstName != "Alicia" || got.Timezone != "Asia/Tokyo" {
			t.Errorf("not set (trimmed): %q %q", got.FirstName, got.Timezone)
		}
		if got.LastName != "Martin" || got.Phone != u.Phone || got.Locale != "fr" {
			t.Errorf("nil fields changed: %+v", got)
		}
	})

	t.Run("never touches the account flags", func(t *testing.T) {
		u := profileTestUser(t, auth)
		if _, err := auth.Repo.UserSetEmailVerified(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := auth.UserSuspend(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
		got, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{LastName: ptr("Dupont")})
		if err != nil {
			t.Fatal(err)
		}
		if got.IsActive || !got.EmailVerified || got.MfaEnabled {
			t.Errorf("flags changed: active=%t emailVerified=%t mfa=%t", got.IsActive, got.EmailVerified, got.MfaEnabled)
		}
	})

	t.Run("an empty update returns the user unchanged", func(t *testing.T) {
		u := profileTestUser(t, auth)
		got, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{})
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != u.ID || got.FirstName != "Alice" {
			t.Errorf("unexpected result %+v", got)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		if _, err := auth.UserProfileUpdate(ctx, util.NewIDStripped(), ProfileUpdate{FirstName: ptr("x")}); err == nil {
			t.Error("expected an error for an unknown user")
		}
	})

	t.Run("usernames are checked and lowercased", func(t *testing.T) {
		u := profileTestUser(t, auth)
		for _, bad := range []string{"ab", "has space", "<b>bold</b>", "waytoolongusernamewaytoolongusername"} {
			if _, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{Username: ptr(bad)}); !errors.Is(err, ErrInvalidUsername) {
				t.Errorf("username %q: expected ErrInvalidUsername, got %v", bad, err)
			}
		}
		name := uniqueName("Mixed_Case")
		got, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{Username: ptr(" " + name + " ")})
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.ToLower(name); got.Username != want {
			t.Errorf("username = %q, want %q", got.Username, want)
		}
		// Clearing a username is allowed.
		if got, err = auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{Username: ptr("")}); err != nil || got.Username != "" {
			t.Errorf("clearing the username: got %q, err %v", got.Username, err)
		}
	})

	t.Run("a username or phone another user has is refused", func(t *testing.T) {
		a, b := profileTestUser(t, auth), profileTestUser(t, auth)
		if _, err := auth.UserProfileUpdate(ctx, b.ID, ProfileUpdate{Username: ptr(a.Username)}); !errors.Is(err, ErrUsernameInUse) {
			t.Errorf("username: expected ErrUsernameInUse, got %v", err)
		}
		if _, err := auth.UserProfileUpdate(ctx, b.ID, ProfileUpdate{Phone: ptr(a.Phone)}); !errors.Is(err, ErrPhoneInUse) {
			t.Errorf("phone: expected ErrPhoneInUse, got %v", err)
		}
		// Re-saving your own values is fine.
		if _, err := auth.UserProfileUpdate(ctx, a.ID, ProfileUpdate{Username: ptr(a.Username), Phone: ptr(a.Phone)}); err != nil {
			t.Errorf("re-saving own username and phone failed: %v", err)
		}
	})

	t.Run("phones are checked", func(t *testing.T) {
		u := profileTestUser(t, auth)
		for _, bad := range []string{"call me", "+123", "+33612345678\nBcc: x"} {
			if _, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{Phone: ptr(bad)}); !errors.Is(err, ErrInvalidPhone) {
				t.Errorf("phone %q: expected ErrInvalidPhone, got %v", bad, err)
			}
		}
	})

	t.Run("changing the phone resets phone_verified, keeping it doesn't", func(t *testing.T) {
		u := profileTestUser(t, auth)
		if _, err := auth.Repo.UserSetPhoneVerified(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
		got, err := auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{Phone: ptr(u.Phone), FirstName: ptr("Same")})
		if err != nil {
			t.Fatal(err)
		}
		if !got.PhoneVerified {
			t.Error("phone_verified was reset although the number didn't change")
		}
		got, err = auth.UserProfileUpdate(ctx, u.ID, ProfileUpdate{Phone: ptr(uniquePhone())})
		if err != nil {
			t.Fatal(err)
		}
		if got.PhoneVerified {
			t.Error("phone_verified stayed true for a new, unverified number")
		}
	})
}

// The repository only writes columns on the allowlist, because the column
// names go into the SQL text.
func TestUserUpdateProfile_RejectsOtherColumns(t *testing.T) {
	ctx := context.Background()
	auth := setupTestDB(t)
	u := profileTestUser(t, auth)

	for _, col := range []string{"email", "password_hash", "is_active", "id", "first_name = '', is_active"} {
		_, err := auth.Repo.UserUpdateProfile(ctx, u.ID, []models.ColumnValue{{Column: col, Value: "x"}})
		if err == nil {
			t.Errorf("column %q was accepted", col)
		}
	}
	stored, err := auth.Repo.UserGetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.IsActive || stored.FirstName != "Alice" {
		t.Errorf("a rejected update changed the user: %+v", stored)
	}
}
