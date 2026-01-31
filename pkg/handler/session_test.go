package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

func TestGetSessionUser_Standalone(t *testing.T) {
	// 1. Context empty
	ctx := context.Background()
	_, err := GetSessionUser(ctx)
	if err == nil {
		t.Error("Expected error when user not in context")
	}

	// 2. Context with user
	user := &models.User{Email: "test@example.com"}
	ctx = context.WithValue(ctx, userObjectContextKey, user)
	got, err := GetSessionUser(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if got.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, got.Email)
	}
}

func TestHandler_GetSessionUser(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	// Create user in DB
	user, err := h.svc.Repo.UserCreate(ctx, &models.User{
		Email: "handler@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Scenario 1: Standalone User Object in Context
	t.Run("Context_UserObject", func(t *testing.T) {
		ctxVal := context.WithValue(ctx, userObjectContextKey, user)
		got, err := h.GetSessionUser(ctxVal)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if got.ID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, got.ID)
		}
	})

	// Scenario 2: UserID in Context (AuthMiddleware simulation)
	t.Run("Context_UserID", func(t *testing.T) {
		ctxVal := context.WithValue(ctx, userContextKey, user.ID)
		got, err := h.GetSessionUser(ctxVal)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if got.ID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, got.ID)
		}
	})

	// Scenario 3: Session Cookies
	t.Run("Session_Cookies", func(t *testing.T) {
		// Mock a session with tokens
		token, err := h.svc.TokenCreate(ctx, user)
		if err != nil {
			t.Fatal(err)
		}

		// Use a request to load the session
		// Manually load the session manager
		ctxVal, err := h.Session.Load(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		// Put tokens in session
		h.Session.Put(ctxVal, sessionTokensKey, map[string]string{
			"access_token":  token.AccessToken,
			"refresh_token": token.RefreshToken,
		})

		// Now test GetSessionUser with this context
		got, err := h.GetSessionUser(ctxVal)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			return
		}
		if got.ID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, got.ID)
		}
	})
}

func TestLoadUserMiddleware(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	// Create user in DB
	user, err := h.svc.Repo.UserCreate(ctx, &models.User{
		Email: "middleware@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Handler that uses the standalone function
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := GetSessionUser(r.Context())
		if err != nil {
			t.Errorf("Standalone GetSessionUser failed inside middleware: %v", err)
			return
		}
		if got.ID != user.ID {
			t.Errorf("Expected user ID %s, got %s", user.ID, got.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Request
	req := httptest.NewRequest("GET", "/", nil)

	// Create a chain: MockAuthMiddleware -> LoadUserMiddleware -> FinalHandler
	mockAuthMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), userContextKey, user.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	chain := mockAuthMiddleware(h.LoadUserMiddleware(finalHandler))

	chain.ServeHTTP(httptest.NewRecorder(), req)
}
