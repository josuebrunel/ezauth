package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
)

var errCheckerFailed = errors.New("checker failed")

// MockTokenGetter mocks the TokenGetter interface
type MockTokenGetter struct {
	Token *models.Token
	Err   error
}

func (m *MockTokenGetter) TokenGetByToken(ctx context.Context, token string) (*models.Token, error) {
	return m.Token, m.Err
}

// MockUserLoader mocks the UserLoader function
func MockUserLoader(user *models.User, err error) UserLoader {
	return func(ctx context.Context) (*models.User, error) {
		return user, err
	}
}

// hs256KeyFunc returns a jwt.Keyfunc that always resolves to secret, for
// testing AuthMiddleware against HS256-signed tokens.
func hs256KeyFunc(secret string) jwt.Keyfunc {
	return func(*jwt.Token) (any, error) { return []byte(secret), nil }
}

func TestAuthMiddleware(t *testing.T) {
	secret := "secret"
	mw := AuthMiddleware(hs256KeyFunc(secret), []string{"HS256"})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := r.Context().Value(UserContextKey).(string)
		if !ok || userID != "user1" {
			t.Errorf("expected userID user1, got %v", userID)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Create valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user1",
	})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_ImpersonatorContextKey(t *testing.T) {
	secret := "secret"
	mw := AuthMiddleware(hs256KeyFunc(secret), []string{"HS256"})

	t.Run("sets impersonator id when act claim present", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, _ := r.Context().Value(UserContextKey).(string)
			if userID != "target1" {
				t.Errorf("expected sub userID target1, got %v", userID)
			}
			actorID, ok := r.Context().Value(ImpersonatorContextKey).(string)
			if !ok || actorID != "admin1" {
				t.Errorf("expected impersonator id admin1, got %v (ok=%v)", actorID, ok)
			}
			w.WriteHeader(http.StatusOK)
		})

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "target1",
			"act": map[string]any{"sub": "admin1"},
		})
		tokenString, _ := token.SignedString([]byte(secret))

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("no impersonator id when act claim absent", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := r.Context().Value(ImpersonatorContextKey).(string); ok {
				t.Error("expected no impersonator id in context for a regular token")
			}
			w.WriteHeader(http.StatusOK)
		})

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user1",
		})
		tokenString, _ := token.SignedString([]byte(secret))

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})
}

func TestAPIKeyMiddleware(t *testing.T) {
	apiKey := "config-key"
	mw := APIKeyMiddleware(apiKey, &MockTokenGetter{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test Config Key
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with config key, got %d", w.Code)
	}

	// Test DB Key (via mock), scoped — confirm the scopes land in context.
	dbKey := "db-key"
	mockRepo := &MockTokenGetter{
		Token: &models.Token{
			TokenType: models.TokenTypeApiKey,
			ExpiresAt: time.Now().Add(time.Hour),
			Metadata:  models.JSONMap{"scopes": []string{"posts:write"}},
		},
	}
	mwDB := APIKeyMiddleware(apiKey, mockRepo)
	nextCheckScopes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes, ok := r.Context().Value(APIKeyScopesContextKey).([]string)
		if !ok || len(scopes) != 1 || scopes[0] != "posts:write" {
			t.Errorf("expected scopes [posts:write] in context, got %v (ok: %v)", scopes, ok)
		}
		w.WriteHeader(http.StatusOK)
	})

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", dbKey)
	w = httptest.NewRecorder()

	mwDB(nextCheckScopes).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with db key, got %d", w.Code)
	}
}

func TestLoadUserMiddleware(t *testing.T) {
	user := &models.User{ID: "user1"}
	loader := MockUserLoader(user, nil)
	mw := LoadUserMiddleware(loader)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := r.Context().Value(UserObjectContextKey).(*models.User)
		if !ok || u.ID != "user1" {
			t.Errorf("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// MockRoleChecker mocks the RoleChecker interface.
type MockRoleChecker struct {
	Has bool
	Err error
}

func (m *MockRoleChecker) UserHasRole(ctx context.Context, userID, role string) (bool, error) {
	return m.Has, m.Err
}

// MockPermissionChecker mocks the PermissionChecker interface.
type MockPermissionChecker struct {
	Has bool
	Err error
}

func (m *MockPermissionChecker) UserHasPermission(ctx context.Context, userID, permission string) (bool, error) {
	return m.Has, m.Err
}

func TestRequireRole(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("NoUserInContext", func(t *testing.T) {
		mw := RequireRole(&MockRoleChecker{Has: true}, "admin")
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 with no user in context, got %d", w.Code)
		}
	})

	t.Run("HasRole", func(t *testing.T) {
		mw := RequireRole(&MockRoleChecker{Has: true}, "admin")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), UserContextKey, "user1"))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 when user has the role, got %d", w.Code)
		}
	})

	t.Run("MissingRole", func(t *testing.T) {
		mw := RequireRole(&MockRoleChecker{Has: false}, "admin")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), UserContextKey, "user1"))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 when user lacks the role, got %d", w.Code)
		}
	})

	t.Run("CheckerError", func(t *testing.T) {
		mw := RequireRole(&MockRoleChecker{Err: errCheckerFailed}, "admin")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), UserContextKey, "user1"))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 when the checker errors, got %d", w.Code)
		}
	})
}

func TestRequirePermission(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("NoUserInContext", func(t *testing.T) {
		mw := RequirePermission(&MockPermissionChecker{Has: true}, "posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 with no user in context, got %d", w.Code)
		}
	})

	t.Run("HasPermission", func(t *testing.T) {
		mw := RequirePermission(&MockPermissionChecker{Has: true}, "posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), UserContextKey, "user1"))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 when user has the permission, got %d", w.Code)
		}
	})

	t.Run("MissingPermission", func(t *testing.T) {
		mw := RequirePermission(&MockPermissionChecker{Has: false}, "posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), UserContextKey, "user1"))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 when user lacks the permission, got %d", w.Code)
		}
	})
}

func TestRequireAPIKeyScope(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("NoAPIKeyContext_Passthrough", func(t *testing.T) {
		// Defensive case: in practice APIKeyMiddleware always runs first and
		// sets this context key for DB-backed keys (the master config key
		// never has one, and is always full-access).
		mw := RequireAPIKeyScope("posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with no api key scopes in context, got %d", w.Code)
		}
	})

	t.Run("Unscoped_Passthrough", func(t *testing.T) {
		mw := RequireAPIKeyScope("posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), APIKeyScopesContextKey, []string{}))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for an unscoped key, got %d", w.Code)
		}
	})

	t.Run("MatchingScope", func(t *testing.T) {
		mw := RequireAPIKeyScope("posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), APIKeyScopesContextKey, []string{"posts:write"}))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 when the key has the required scope, got %d", w.Code)
		}
	})

	t.Run("MissingScope", func(t *testing.T) {
		mw := RequireAPIKeyScope("posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), APIKeyScopesContextKey, []string{"posts:read"}))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 when the key lacks the required scope, got %d", w.Code)
		}
	})
}
