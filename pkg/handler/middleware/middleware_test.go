package middleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
)

var errCheckerFailed = errors.New("checker failed")

// MockTokenGetter mocks the TokenGetter interface
type MockTokenGetter struct {
	Token *models.Token
	Err   error

	// ReceivedToken records the value the caller looked up with, so tests
	// can assert on it (e.g. that it was hashed, not the raw value).
	ReceivedToken string
}

func (m *MockTokenGetter) TokenGetByToken(ctx context.Context, token string) (*models.Token, error) {
	m.ReceivedToken = token
	return m.Token, m.Err
}

// MockUserLoader mocks the UserLoader function
func MockUserLoader(user *models.User, err error) UserLoader {
	return func(ctx context.Context) (*models.User, error) {
		return user, err
	}
}

// MockUserActiveGetter mocks the UserActiveGetter interface. Defaults (zero
// value) to an active user unless User/Err are set, so existing tests that
// don't care about this check can use &MockUserActiveGetter{} and still get
// an IsActive user back.
type MockUserActiveGetter struct {
	User *models.User
	Err  error
}

func (m *MockUserActiveGetter) UserGetByID(ctx context.Context, id string) (*models.User, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if m.User != nil {
		return m.User, nil
	}
	return &models.User{ID: id, IsActive: true}, nil
}

// hs256KeyFunc returns a jwt.Keyfunc that always resolves to secret, for
// testing AuthMiddleware against HS256-signed tokens.
func hs256KeyFunc(secret string) jwt.Keyfunc {
	return func(*jwt.Token) (any, error) { return []byte(secret), nil }
}

func TestAuthMiddleware(t *testing.T) {
	secret := "secret"
	mw := AuthMiddleware(hs256KeyFunc(secret), []string{"HS256"}, &MockUserActiveGetter{})
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
	mw := AuthMiddleware(hs256KeyFunc(secret), []string{"HS256"}, &MockUserActiveGetter{})

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
	mw := APIKeyMiddleware(apiKey, &MockTokenGetter{}, &MockUserActiveGetter{})

	// Test Config Key -- also confirm it sets APIKeyScopesContextKey (to an
	// explicit unscoped []string{}) like the DB-key path does, so
	// RequireAPIKeyScope downstream can tell "authenticated, unscoped" apart
	// from "APIKeyMiddleware never ran".
	nextCheckMasterKeyScopes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopes, ok := r.Context().Value(APIKeyScopesContextKey).([]string)
		if !ok || len(scopes) != 0 {
			t.Errorf("expected an explicit empty scopes slice in context for the master key, got %v (ok: %v)", scopes, ok)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()

	mw(nextCheckMasterKeyScopes).ServeHTTP(w, req)
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
	mwDB := APIKeyMiddleware(apiKey, mockRepo, &MockUserActiveGetter{})
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

// TestAPIKeyMiddleware_LooksUpByHash proves APIKeyMiddleware hashes the
// X-API-Key header value before looking it up (see util.HashToken), not the
// raw key -- API keys are stored hashed, so a plaintext lookup would never
// match.
func TestAPIKeyMiddleware_LooksUpByHash(t *testing.T) {
	mockRepo := &MockTokenGetter{
		Token: &models.Token{TokenType: models.TokenTypeApiKey, ExpiresAt: time.Now().Add(time.Hour)},
	}
	mw := APIKeyMiddleware("config-key", mockRepo, &MockUserActiveGetter{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	rawKey := "some-raw-db-api-key-value"
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", rawKey)
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if mockRepo.ReceivedToken == rawKey {
		t.Fatal("APIKeyMiddleware looked up the raw key value instead of its hash")
	}
	if want := util.HashToken(rawKey); mockRepo.ReceivedToken != want {
		t.Fatalf("expected lookup with hash %q, got %q", want, mockRepo.ReceivedToken)
	}
}

// TestAuthMiddleware_RejectsInactiveUser proves a Bearer token with a valid
// signature and unexpired claims still fails once the owning user has been
// suspended -- before #202/#203, only signature/expiry/algorithm were
// checked, so a suspended account kept Bearer access until the access
// token's own natural expiry.
func TestAuthMiddleware_RejectsInactiveUser(t *testing.T) {
	secret := "secret"
	mw := AuthMiddleware(hs256KeyFunc(secret), []string{"HS256"}, &MockUserActiveGetter{
		User: &models.User{ID: "user1", IsActive: false},
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("expected the suspended user's token to be rejected before reaching next")
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user1"})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a suspended user, got %d", w.Code)
	}
}

// TestAuthMiddleware_RejectsWhenUserLookupFails proves a token for a
// since-deleted user (UserGetByID errors, e.g. sql.ErrNoRows) is rejected
// rather than treated as still authenticated.
func TestAuthMiddleware_RejectsWhenUserLookupFails(t *testing.T) {
	secret := "secret"
	mw := AuthMiddleware(hs256KeyFunc(secret), []string{"HS256"}, &MockUserActiveGetter{
		Err: errCheckerFailed,
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("expected the lookup failure to reject before reaching next")
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "deleted-user"})
	tokenString, _ := token.SignedString([]byte(secret))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when the user lookup fails, got %d", w.Code)
	}
}

// TestAPIKeyMiddleware_RejectsInactiveUser proves a still-valid (unrevoked,
// unexpired) DB-backed API key stops working once its owning user is
// suspended -- before #203, only the token row's own fields were checked.
func TestAPIKeyMiddleware_RejectsInactiveUser(t *testing.T) {
	mockRepo := &MockTokenGetter{
		Token: &models.Token{UserID: "user1", TokenType: models.TokenTypeApiKey, ExpiresAt: time.Now().Add(time.Hour)},
	}
	mw := APIKeyMiddleware("config-key", mockRepo, &MockUserActiveGetter{
		User: &models.User{ID: "user1", IsActive: false},
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("expected the suspended user's API key to be rejected before reaching next")
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "db-key")
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a suspended user's API key, got %d", w.Code)
	}
}

// TestAPIKeyMiddleware_MasterKeyBypassesUserCheck proves the shared config
// master key (which has no owning user at all) still authenticates even
// though UserActiveGetter would reject any real user ID -- the check only
// applies to DB-backed, user-owned keys.
func TestAPIKeyMiddleware_MasterKeyBypassesUserCheck(t *testing.T) {
	mw := APIKeyMiddleware("config-key", &MockTokenGetter{}, &MockUserActiveGetter{
		Err: errCheckerFailed,
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "config-key")
	w := httptest.NewRecorder()

	mw(next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected the master key to bypass the per-user check, got %d", w.Code)
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

// MockOrgMembershipChecker mocks the OrgMembershipChecker interface.
type MockOrgMembershipChecker struct {
	RoleName string
	IsMember bool
	Err      error
}

func (m *MockOrgMembershipChecker) OrgMemberRole(ctx context.Context, orgID, userID string) (string, bool, error) {
	return m.RoleName, m.IsMember, m.Err
}

func TestRequireOrgMembership(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	reqWithUserAndOrg := func(userID, orgID string) *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := req.Context()
		if userID != "" {
			ctx = context.WithValue(ctx, UserContextKey, userID)
		}
		if orgID != "" {
			ctx = context.WithValue(ctx, OrgContextKey, orgID)
		}
		return req.WithContext(ctx)
	}

	t.Run("NoUserInContext", func(t *testing.T) {
		mw := RequireOrgMembership(&MockOrgMembershipChecker{IsMember: true})
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("", "org1"))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 with no user in context, got %d", w.Code)
		}
	})

	t.Run("NoOrgInContext", func(t *testing.T) {
		mw := RequireOrgMembership(&MockOrgMembershipChecker{IsMember: true})
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("user1", ""))
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 with no org in context, got %d", w.Code)
		}
	})

	t.Run("IsMember", func(t *testing.T) {
		mw := RequireOrgMembership(&MockOrgMembershipChecker{IsMember: true, RoleName: "viewer"})
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("user1", "org1"))
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for a member of any role, got %d", w.Code)
		}
	})

	t.Run("NotMember", func(t *testing.T) {
		mw := RequireOrgMembership(&MockOrgMembershipChecker{IsMember: false})
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("user1", "org1"))
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for a non-member, got %d", w.Code)
		}
	})

	t.Run("CheckerError", func(t *testing.T) {
		mw := RequireOrgMembership(&MockOrgMembershipChecker{IsMember: true, Err: errCheckerFailed})
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("user1", "org1"))
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 when the checker errors, got %d", w.Code)
		}
	})
}

func TestRequireOrgRole(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	reqWithUserAndOrg := func(userID, orgID string) *http.Request {
		req := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(req.Context(), UserContextKey, userID)
		ctx = context.WithValue(ctx, OrgContextKey, orgID)
		return req.WithContext(ctx)
	}

	t.Run("HasExactRole", func(t *testing.T) {
		mw := RequireOrgRole(&MockOrgMembershipChecker{IsMember: true, RoleName: "org-admin"}, "org-admin")
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("user1", "org1"))
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for the exact required role, got %d", w.Code)
		}
	})

	t.Run("WrongRole", func(t *testing.T) {
		mw := RequireOrgRole(&MockOrgMembershipChecker{IsMember: true, RoleName: "viewer"}, "org-admin")
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("user1", "org1"))
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for a member with a different role, got %d", w.Code)
		}
	})

	t.Run("NotMember", func(t *testing.T) {
		mw := RequireOrgRole(&MockOrgMembershipChecker{IsMember: false}, "org-admin")
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, reqWithUserAndOrg("user1", "org1"))
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for a non-member, got %d", w.Code)
		}
	})
}

func TestRequireAPIKeyScope(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("NoAPIKeyContext_RejectsClosed", func(t *testing.T) {
		// A missing context value means APIKeyMiddleware never ran on this
		// route at all (e.g. a custom router wired without it) -- there is
		// no authentication whatsoever, so this must fail closed rather than
		// wave the request through. APIKeyMiddleware itself always sets this
		// key on success now, including the master config key path.
		mw := RequireAPIKeyScope("posts:write")
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 with no api key scopes in context, got %d", w.Code)
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

func TestOrgLoaderMiddleware(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		org := &models.Organization{ID: "org1"}
		loader := OrgLoader(func(ctx context.Context) (*models.Organization, error) {
			return org, nil
		})
		mw := OrgLoaderMiddleware(loader)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			o, ok := r.Context().Value(OrgObjectContextKey).(*models.Organization)
			if !ok || o.ID != "org1" {
				t.Errorf("expected org in context")
			}
			orgID, ok := r.Context().Value(OrgContextKey).(string)
			if !ok || orgID != "org1" {
				t.Errorf("expected org id in context")
			}
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("LoaderError_NoContextSet", func(t *testing.T) {
		loader := OrgLoader(func(ctx context.Context) (*models.Organization, error) {
			return nil, errCheckerFailed
		})
		mw := OrgLoaderMiddleware(loader)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := r.Context().Value(OrgObjectContextKey).(*models.Organization); ok {
				t.Error("expected no org in context when the loader errors")
			}
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 (passthrough), got %d", w.Code)
		}
	})
}

func TestMaxBodyBytes(t *testing.T) {
	const limit = 16

	mw := MaxBodyBytes(limit)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	t.Run("body within limit passes through", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", limit)))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("body over limit is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("a", limit*10)))
		w := httptest.NewRecorder()

		mw(next).ServeHTTP(w, req)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("expected 413, got %d", w.Code)
		}
	})
}

type mockAuthChecker struct{ authenticated bool }

func (m mockAuthChecker) IsAuthenticated(ctx context.Context) bool { return m.authenticated }

func TestLoginRequiredMiddleware(t *testing.T) {
	const loginPath = "/login"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("authenticated request passes through", func(t *testing.T) {
		mw := LoginRequiredMiddleware(mockAuthChecker{authenticated: true}, loginPath)
		req := httptest.NewRequest("GET", "/anything", nil)
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("unauthenticated browser request redirects to login", func(t *testing.T) {
		mw := LoginRequiredMiddleware(mockAuthChecker{authenticated: false}, loginPath)
		req := httptest.NewRequest("GET", "/dashboard", nil)
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusFound {
			t.Errorf("expected 302, got %d", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != loginPath {
			t.Errorf("expected redirect to %q, got %q", loginPath, loc)
		}
	})

	// The path itself must never decide this -- a consuming app mounts this
	// middleware on its own routes, at any prefix, not just ezauth's own
	// "/auth/api" subtree.
	t.Run("unauthenticated request to a non-auth-api path with Accept: application/json gets a 401, not a redirect", func(t *testing.T) {
		mw := LoginRequiredMiddleware(mockAuthChecker{authenticated: false}, loginPath)
		req := httptest.NewRequest("GET", "/some/other/api/path", nil)
		req.Header.Set("Accept", "application/json")
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})

	t.Run("unauthenticated request with Content-Type: application/json gets a 401", func(t *testing.T) {
		mw := LoginRequiredMiddleware(mockAuthChecker{authenticated: false}, loginPath)
		req := httptest.NewRequest("POST", "/some/other/path", nil)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})

	t.Run("unauthenticated request to /auth/api without a JSON Accept/Content-Type redirects", func(t *testing.T) {
		mw := LoginRequiredMiddleware(mockAuthChecker{authenticated: false}, loginPath)
		req := httptest.NewRequest("GET", "/auth/api/userinfo", nil)
		w := httptest.NewRecorder()
		mw(next).ServeHTTP(w, req)
		if w.Code != http.StatusFound {
			t.Errorf("expected 302 (path alone must not decide this), got %d", w.Code)
		}
	})
}
