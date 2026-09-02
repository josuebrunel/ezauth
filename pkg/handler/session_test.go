package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func TestGetSessionUser_Standalone(t *testing.T) {
	// 1. Context empty
	ctx := context.Background()
	_, err := GetSessionUser(ctx)
	if err == nil {
		t.Error("Expected error when user not in context")
	}

	// 2. Context with user
	user := &models.User{Email: util.UniqueEmail("test")}
	ctx = context.WithValue(ctx, ezmiddleware.UserObjectContextKey, user)
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
		Email: util.UniqueEmail("handler"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Scenario 1: Standalone User Object in Context
	t.Run("Context_UserObject", func(t *testing.T) {
		ctxVal := context.WithValue(ctx, ezmiddleware.UserObjectContextKey, user)
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
		ctxVal := context.WithValue(ctx, ezmiddleware.UserContextKey, user.ID)
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
		Email: util.UniqueEmail("middleware"),
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
			ctx := context.WithValue(r.Context(), ezmiddleware.UserContextKey, user.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	chain := mockAuthMiddleware(h.LoadUserMiddleware(finalHandler))

	chain.ServeHTTP(httptest.NewRecorder(), req)
}

func TestGetSessionTokens_WithoutSessionMiddleware(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic when session middleware is not loaded")
		}
	}()

	// This should panic without session middleware loaded (fails fast on programming error)
	h.GetSessionTokens(ctx)
}

func TestLoadUserMiddleware_WithoutSessionMiddleware(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	// Create user in DB
	user, err := h.svc.Repo.UserCreate(ctx, &models.User{
		Email: util.UniqueEmail("middleware-no-session"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Handler that expects the user to be in context
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
	// WITHOUT session middleware, this should not panic
	mockAuthMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ezmiddleware.UserContextKey, user.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	chain := mockAuthMiddleware(h.LoadUserMiddleware(finalHandler))

	// This should not panic even without session middleware
	chain.ServeHTTP(httptest.NewRecorder(), req)
}

func TestStashSessionContext(t *testing.T) {
	h := &Handler{Session: scs.New()}

	// Load an (empty) session into the context, as LoadAndSaveMiddleware does.
	ctx, err := h.Session.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	h.Session.Put(ctx, sessionTokensKey, map[string]string{
		"access_token":  "at-1",
		"refresh_token": "rt-1",
	})
	h.Session.Put(ctx, sessionImpersonatorIDKey, "admin-1")

	out := h.stashSessionContext(ctx)

	tokens, ok := GetSessionTokens(out)
	if !ok {
		t.Fatal("expected session tokens to be stashed into the context")
	}
	if tokens["access_token"] != "at-1" || tokens["refresh_token"] != "rt-1" {
		t.Errorf("unexpected tokens: %v", tokens)
	}

	id, ok := CurrentImpersonatorID(out)
	if !ok || id != "admin-1" {
		t.Errorf("expected stashed impersonator admin-1, got %q ok=%v", id, ok)
	}

	// Stashing must not disturb the underlying session.
	if got, ok := h.Session.Get(ctx, sessionImpersonatorIDKey).(string); !ok || got != "admin-1" {
		t.Errorf("session impersonator id changed: %q ok=%v", got, ok)
	}
}

func TestStashSessionContext_EmptySession(t *testing.T) {
	h := &Handler{Session: scs.New()}
	ctx, err := h.Session.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}

	out := h.stashSessionContext(ctx)

	if _, ok := GetSessionTokens(out); ok {
		t.Error("expected no session tokens for an empty session")
	}
	if _, ok := CurrentImpersonatorID(out); ok {
		t.Error("expected no impersonator for an empty session")
	}
}

func TestGetSessionTokens_Standalone(t *testing.T) {
	if tokens, ok := GetSessionTokens(context.Background()); ok {
		t.Errorf("expected no tokens without SessionMiddleware, got %v", tokens)
	}

	ctx := context.WithValue(context.Background(), ezmiddleware.SessionTokensContextKey, map[string]string{
		"access_token": "at-2",
	})
	tokens, ok := GetSessionTokens(ctx)
	if !ok || tokens["access_token"] != "at-2" {
		t.Errorf("expected stashed access token, got %v ok=%v", tokens, ok)
	}
}

func TestCurrentImpersonatorID_JWTFallback(t *testing.T) {
	// No cookie session stash — falls back to the Bearer/JWT "act" claim.
	ctx := context.WithValue(context.Background(), ezmiddleware.ImpersonatorContextKey, "admin-2")
	id, ok := CurrentImpersonatorID(ctx)
	if !ok || id != "admin-2" {
		t.Errorf("expected JWT impersonator admin-2, got %q ok=%v", id, ok)
	}

	if id, ok := CurrentImpersonatorID(context.Background()); ok || id != "" {
		t.Errorf("expected no impersonator on an empty context, got %q ok=%v", id, ok)
	}
}
