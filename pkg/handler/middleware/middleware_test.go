package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
)

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

	// Test DB Key (via mock)
	dbKey := "db-key"
	mockRepo := &MockTokenGetter{
		Token: &models.Token{
			TokenType: models.TokenTypeApiKey,
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
	mwDB := APIKeyMiddleware(apiKey, mockRepo)

	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", dbKey)
	w = httptest.NewRecorder()

	mwDB(next).ServeHTTP(w, req)
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
