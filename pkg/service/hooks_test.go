package service

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

func TestHooks(t *testing.T) {
	ctx := context.Background()
	user := &models.User{Email: "test@example.com"}

	t.Run("nil hooks should not panic", func(t *testing.T) {
		hooks := &Hooks{}
		err := CallHook(hooks.OnUserCreated, ctx, user)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		err = CallHookWithProvider(hooks.OnOAuth2SignedIn, ctx, user, "google")
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("hooks should be called", func(t *testing.T) {
		called := false
		hooks := &Hooks{
			OnUserCreated: func(ctx context.Context, u *models.User) error {
				called = true
				if u.Email != user.Email {
					t.Errorf("expected email %s, got %s", user.Email, u.Email)
				}
				return nil
			},
		}

		err := CallHook(hooks.OnUserCreated, ctx, user)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if !called {
			t.Error("expected hook to be called")
		}
	})

	t.Run("hooks with provider should be called", func(t *testing.T) {
		called := false
		providerName := "google"
		hooks := &Hooks{
			OnOAuth2SignedIn: func(ctx context.Context, u *models.User, p string) error {
				called = true
				if p != providerName {
					t.Errorf("expected provider %s, got %s", providerName, p)
				}
				return nil
			},
		}

		err := CallHookWithProvider(hooks.OnOAuth2SignedIn, ctx, user, providerName)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if !called {
			t.Error("expected hook to be called")
		}
	})
}
