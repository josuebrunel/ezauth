package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

// newAdminAuthzTestHandler builds a Handler with both JSON and Form routes
// usable (Redirects/Pages set, matching setupFormTestHandler), so a single
// suite can exercise the admin/RBAC/org/impersonation gate (see
// WithAdminAuthz) on both transports.
func newAdminAuthzTestHandler(t *testing.T, opts ...HandlerOption) *Handler {
	t.Helper()
	dialect, dsn := util.GetTestDBConfig("admin_authz_test")

	cfg := &config.Config{
		DB:        config.Database{Dialect: dialect, DSN: dsn},
		JWTSecret: "test-secret",
		Hashing:   config.Hashing{BcryptCost: 4},
		Addr:      ":8080",
		ApiKey:    "test-api-key",
		Redirects: config.Redirects{AfterLogin: "/dashboard", AfterRegister: "/onboarding"},
		Pages:     config.Pages{Login: "/login", Register: "/register"},
	}
	authSvc, err := service.NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := ensureMigrated(authSvc.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return New(authSvc, "auth", opts...)
}

func TestAdminAuthz_JSON_Default(t *testing.T) {
	h := newAdminAuthzTestHandler(t)
	user, accessToken, _ := registerAndLogin(t, h, "plain-user")

	getAdminUsers := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	t.Run("non-admin authenticated user is forbidden", func(t *testing.T) {
		if code := getAdminUsers(accessToken); code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", code)
		}
	})

	t.Run("unauthenticated request is unauthorized, not forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/admin/users", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("granting the admin role allows access", func(t *testing.T) {
		grantAdminRole(t, h, user.ID)
		if code := getAdminUsers(accessToken); code != http.StatusOK {
			t.Fatalf("expected 200 after granting admin role, got %d", code)
		}
	})

	t.Run("non-admin cannot impersonate", func(t *testing.T) {
		target, _, _ := registerAndLogin(t, h, "impersonate-target-json")
		reqBody := map[string]any{"target_user_id": target.ID}
		body, _ := json.Marshal(reqBody)
		_, nonAdminAccess, _ := registerAndLogin(t, h, "another-plain-user")

		req := httptest.NewRequest(http.MethodPost, "/auth/api/impersonate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+nonAdminAccess)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestAdminAuthz_Form_Default(t *testing.T) {
	h := newAdminAuthzTestHandler(t)
	email := util.UniqueEmail("form-plain-user")
	password := "password123"
	formRegister(t, h, email, password)
	cookie := formLogin(t, h, email, password)
	user := formSessionUser(t, h, cookie)

	getAdminUsers := func(cookie *http.Cookie) int {
		req := httptest.NewRequest(http.MethodGet, "/auth/admin/users", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	t.Run("non-admin session gets a JSON 403, matching the handler's own pre-existing auth-failure convention", func(t *testing.T) {
		if code := getAdminUsers(cookie); code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", code)
		}
	})

	t.Run("granting the admin role allows access", func(t *testing.T) {
		grantAdminRole(t, h, user.ID)
		if code := getAdminUsers(cookie); code != http.StatusOK {
			t.Fatalf("expected 200 after granting admin role, got %d", code)
		}
	})

	t.Run("non-admin session is redirected away from impersonate, not shown a JSON body", func(t *testing.T) {
		otherEmail := util.UniqueEmail("form-plain-user2")
		formRegister(t, h, otherEmail, password)
		otherCookie := formLogin(t, h, otherEmail, password)
		target := formSessionUser(t, h, otherCookie)

		form := url.Values{}
		form.Add("target_user_id", target.ID)
		req := httptest.NewRequest(http.MethodPost, "/auth/impersonate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(otherCookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected a 302 redirect (matching FormImpersonate's other error paths), got %d: %s", w.Code, w.Body.String())
		}
		// Session must still resolve to the original (non-admin) user --
		// impersonation must not have started.
		if got := formSessionUser(t, h, otherCookie); got.ID != target.ID {
			t.Fatalf("expected session to still resolve to the original non-admin user, got %s", got.Email)
		}
	})
}

func TestAdminAuthz_CustomOverride(t *testing.T) {
	var called bool
	custom := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			next.ServeHTTP(w, r) // always allows, to prove this replaced the default check
		})
	}
	h := newAdminAuthzTestHandler(t, WithAdminAuthz(custom))

	_, accessToken, _ := registerAndLogin(t, h, "custom-authz-user")
	req := httptest.NewRequest(http.MethodGet, "/auth/api/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !called {
		t.Fatal("expected the custom WithAdminAuthz middleware to run")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected the custom middleware's always-allow decision to be honored (200), got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminAuthz_Disabled(t *testing.T) {
	h := newAdminAuthzTestHandler(t, WithAdminAuthz(nil))

	t.Run("JSON API: any authenticated user reaches admin routes", func(t *testing.T) {
		_, accessToken, _ := registerAndLogin(t, h, "disabled-authz-user")
		req := httptest.NewRequest(http.MethodGet, "/auth/api/admin/users", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 with admin authz disabled, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("Form: impersonation succeeds for any logged-in session", func(t *testing.T) {
		adminEmail := util.UniqueEmail("disabled-form-admin")
		targetEmail := util.UniqueEmail("disabled-form-target")
		password := "password123"
		formRegister(t, h, adminEmail, password)
		formRegister(t, h, targetEmail, password)
		adminCookie := formLogin(t, h, adminEmail, password)
		target := formSessionUser(t, h, formLogin(t, h, targetEmail, password))

		form := url.Values{}
		form.Add("target_user_id", target.ID)
		req := httptest.NewRequest(http.MethodPost, "/auth/impersonate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(adminCookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
		}
		if len(w.Result().Cookies()) == 0 {
			t.Fatal("expected a session cookie to be set")
		}
		impersonatedCookie := w.Result().Cookies()[0]
		if got := formSessionUser(t, h, impersonatedCookie); got.ID != target.ID {
			t.Fatalf("expected session to resolve to target after impersonate, got %s", got.Email)
		}
	})
}
