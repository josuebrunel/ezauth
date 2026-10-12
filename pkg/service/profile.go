package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

var (
	// ErrInvalidUsername is returned when a username breaks the registration rules.
	ErrInvalidUsername = errors.New("username must be 3-30 characters: letters, numbers, underscores, hyphens")
	// ErrUsernameInUse is returned when another user already has the username.
	ErrUsernameInUse = errors.New("another user already has that username")
	// ErrPhoneInUse is returned when another user already has the phone number.
	ErrPhoneInUse = errors.New("another user already has that phone number")
)

// ProfileUpdate is a partial update of a user's profile. Each field says one
// of three things: nil leaves it unchanged, a value sets it, and a pointer to
// the empty string clears it. UserUpdate can't express the last one, because
// it skips every empty field.
type ProfileUpdate struct {
	FirstName *string
	LastName  *string
	Username  *string
	Phone     *string
	Locale    *string
	Timezone  *string
	AvatarURL *string
	Nickname  *string
}

// UserProfileUpdate applies a ProfileUpdate to a user and returns the result.
// Only the fields that are set are written, the account flags are never
// touched, and updated_at is bumped. It checks usernames and phone numbers
// against the registration rules, lowercases the username like UserUpdate
// does, and refuses a username or phone another user already has. Changing
// the phone number resets phone_verified, because the new number hasn't been
// verified. ezauth performs no authorization check here; the caller must
// verify the requester may edit this user, and run the Before/AfterUserUpdated
// hooks if it wants them.
func (a *Auth) UserProfileUpdate(ctx context.Context, userID string, u ProfileUpdate) (*models.User, error) {
	current, err := a.Repo.UserGetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	var cols []models.ColumnValue
	add := func(column string, v *string, normalize func(string) string) {
		if v == nil {
			return
		}
		cols = append(cols, models.ColumnValue{Column: column, Value: normalize(*v)})
	}
	trim := strings.TrimSpace
	lower := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

	add(models.ColumnFirstName, u.FirstName, trim)
	add(models.ColumnLastName, u.LastName, trim)
	add(models.ColumnLocale, u.Locale, trim)
	add(models.ColumnTimezone, u.Timezone, trim)
	add(models.ColumnAvatarURL, u.AvatarURL, trim)
	add(models.ColumnNickname, u.Nickname, trim)
	add(models.ColumnUsername, u.Username, lower)
	add(models.ColumnPhone, u.Phone, trim)

	phoneChanged := false
	for _, c := range cols {
		switch c.Column {
		case models.ColumnUsername:
			if c.Value == "" {
				continue
			}
			if !usernameRegex.MatchString(c.Value) {
				return nil, ErrInvalidUsername
			}
			if other, err := a.Repo.UserGetByUsername(ctx, c.Value); err == nil && other.ID != userID {
				return nil, ErrUsernameInUse
			}
		case models.ColumnPhone:
			phoneChanged = c.Value != current.Phone
			if c.Value == "" {
				continue
			}
			if err := validatePhone(c.Value); err != nil {
				return nil, err
			}
			if other, err := a.Repo.UserGetByPhone(ctx, c.Value); err == nil && other.ID != userID {
				return nil, ErrPhoneInUse
			}
		}
	}

	updated, err := a.Repo.UserUpdateProfile(ctx, userID, cols)
	if err != nil {
		return nil, fmt.Errorf("update profile: %w", err)
	}
	if phoneChanged && updated.PhoneVerified {
		if updated, err = a.Repo.UserSetPhoneVerified(ctx, userID, false); err != nil {
			return nil, fmt.Errorf("reset phone verification: %w", err)
		}
	}
	return updated, nil
}
