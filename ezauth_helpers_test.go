package ezauth

import (
	"context"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
)

func TestHelpers(t *testing.T) {
	t.Run("GetUserID", func(t *testing.T) {
		userID := "test-user-id"
		ctx := context.WithValue(context.Background(), ezmiddleware.UserContextKey, userID)

		id, err := GetUserID(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != userID {
			t.Fatalf("expected user ID %s, got %s", userID, id)
		}

		// Test error case
		_, err = GetUserID(context.Background())
		if err == nil {
			t.Fatal("expected error when user ID is missing from context")
		}
	})

	t.Run("GetUser", func(t *testing.T) {
		user := &models.User{ID: "test-user-id", Email: "test@example.com"}
		ctx := context.WithValue(context.Background(), ezmiddleware.UserObjectContextKey, user)

		u, err := GetUser(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.ID != user.ID {
			t.Fatalf("expected user ID %s, got %s", user.ID, u.ID)
		}

		// Test error case
		_, err = GetUser(context.Background())
		if err == nil {
			t.Fatal("expected error when user object is missing from context")
		}
	})

	t.Run("IsAuthenticated", func(t *testing.T) {
		// Case 1: User Object in Context
		user := &models.User{ID: "test-user-id"}
		ctx1 := context.WithValue(context.Background(), ezmiddleware.UserObjectContextKey, user)
		if !IsAuthenticated(ctx1) {
			t.Fatal("expected true when user object is in context")
		}

		// Case 2: User ID in Context
		ctx2 := context.WithValue(context.Background(), ezmiddleware.UserContextKey, "some-id")
		if !IsAuthenticated(ctx2) {
			t.Fatal("expected true when user ID is in context")
		}

		// Case 3: Not Authenticated
		if IsAuthenticated(context.Background()) {
			t.Fatal("expected false when context is empty")
		}
	})
}
