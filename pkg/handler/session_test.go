package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
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

// stashRefreshTokenInSession loads a fresh scs session context and stashes
// rawRefreshToken as the cookie session's refresh token, the same shape
// GetSessionUser's fallback (cookie-session) lookup path expects.
func stashRefreshTokenInSession(t *testing.T, h *Handler, rawRefreshToken string) context.Context {
	t.Helper()
	ctxVal, err := h.Session.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	h.Session.Put(ctxVal, sessionTokensKey, map[string]string{
		"access_token":  "irrelevant-for-this-test",
		"refresh_token": rawRefreshToken,
	})
	return ctxVal
}

// TestHandler_GetSessionUser_RejectsRevokedToken proves a cookie session
// backed by a revoked refresh token (e.g. after logout, "log out
// everywhere", or a password reset elsewhere) no longer authenticates, and
// that the now-useless session is destroyed rather than re-presented. See
// #202: this row-validation was entirely missing before.
func TestHandler_GetSessionUser_RejectsRevokedToken(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	user, err := h.svc.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("revoked")})
	if err != nil {
		t.Fatal(err)
	}
	tokenResp, err := h.svc.TokenCreate(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	row, err := h.svc.Repo.TokenGetByToken(ctx, util.HashToken(tokenResp.RefreshToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Repo.TokenRevoke(ctx, row.ID); err != nil {
		t.Fatal(err)
	}

	ctxVal := stashRefreshTokenInSession(t, h, tokenResp.RefreshToken)
	if _, err := h.GetSessionUser(ctxVal); err == nil {
		t.Fatal("expected a revoked refresh token to fail authentication")
	}
	if _, ok := h.GetSessionTokens(ctxVal); ok {
		t.Error("expected the session to be destroyed after rejecting a revoked token")
	}
}

// TestHandler_GetSessionUser_RejectsExpiredToken proves an expired refresh
// token stops authenticating a cookie session even while the (much
// longer-lived) scs session cookie itself is still valid.
func TestHandler_GetSessionUser_RejectsExpiredToken(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	user, err := h.svc.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("expired")})
	if err != nil {
		t.Fatal(err)
	}
	rawToken := util.NewIDStripped()
	_, err = h.svc.Repo.TokenCreate(ctx, &models.Token{
		ID:        util.NewIDStripped(),
		UserID:    user.ID,
		Token:     util.HashToken(rawToken),
		TokenType: models.TokenTypeRefresh,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctxVal := stashRefreshTokenInSession(t, h, rawToken)
	if _, err := h.GetSessionUser(ctxVal); err == nil {
		t.Fatal("expected an expired refresh token to fail authentication")
	}
	if _, ok := h.GetSessionTokens(ctxVal); ok {
		t.Error("expected the session to be destroyed after rejecting an expired token")
	}
}

// TestHandler_GetSessionUser_RejectsInactiveUser proves a valid, unexpired
// refresh token still fails cookie-session authentication once the owning
// user has been suspended.
func TestHandler_GetSessionUser_RejectsInactiveUser(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	user, err := h.svc.Repo.UserCreate(ctx, &models.User{Email: util.UniqueEmail("suspended")})
	if err != nil {
		t.Fatal(err)
	}
	tokenResp, err := h.svc.TokenCreate(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Repo.UserSetLockoutState(ctx, user.ID, 0, nil, false); err != nil {
		t.Fatal(err)
	}

	ctxVal := stashRefreshTokenInSession(t, h, tokenResp.RefreshToken)
	if _, err := h.GetSessionUser(ctxVal); err == nil {
		t.Fatal("expected a suspended user's refresh token to fail authentication")
	}
	if _, ok := h.GetSessionTokens(ctxVal); ok {
		t.Error("expected the session to be destroyed after rejecting a suspended user")
	}
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

// TestSetAuthCookies_RenewsSessionToken guards against session fixation: a
// session token issued before login must not still be valid after login, so
// setAuthCookies must rotate it (scs.SessionManager.RenewToken) before
// storing the auth tokens.
func TestSetAuthCookies_RenewsSessionToken(t *testing.T) {
	h := &Handler{Session: scs.New()}

	ctx, err := h.Session.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	preLoginToken := h.Session.Token(ctx)

	tokenResp := &service.TokenResponse{AccessToken: "access", RefreshToken: "refresh"}
	if err := h.setAuthCookies(ctx, tokenResp); err != nil {
		t.Fatalf("setAuthCookies failed: %v", err)
	}

	if got := h.Session.Token(ctx); got == preLoginToken {
		t.Error("expected session token to be renewed on login, but it did not change")
	}

	tokens, ok := GetSessionTokens(h.stashSessionContext(ctx))
	if !ok || tokens["access_token"] != "access" || tokens["refresh_token"] != "refresh" {
		t.Errorf("expected auth tokens to still be set after renewal, got %v ok=%v", tokens, ok)
	}
}

// TestSetImpersonationCookies_RenewsSessionToken covers the same fixation
// guard for the impersonation-start path, which is itself a privilege-level
// change, while confirming the impersonator stash written just before the
// renewal survives it (RenewToken migrates session data, it doesn't drop it).
func TestSetImpersonationCookies_RenewsSessionToken(t *testing.T) {
	h := &Handler{Session: scs.New()}

	ctx, err := h.Session.Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	preToken := h.Session.Token(ctx)

	tokenResp := &service.TokenResponse{AccessToken: "target-access", RefreshToken: "target-refresh"}
	if err := h.setImpersonationCookies(ctx, "admin-1", tokenResp); err != nil {
		t.Fatalf("setImpersonationCookies failed: %v", err)
	}

	if got := h.Session.Token(ctx); got == preToken {
		t.Error("expected session token to be renewed on impersonation start, but it did not change")
	}

	if got, ok := h.Session.Get(ctx, sessionImpersonatorIDKey).(string); !ok || got != "admin-1" {
		t.Errorf("expected impersonator id admin-1 to survive renewal, got %q ok=%v", got, ok)
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
