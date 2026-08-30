package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

func setupFormTestHandler(t *testing.T) *Handler {
	dialect, dsn := util.GetTestDBConfig("form_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
		Addr:      ":8080",
		ApiKey:    "test-api-key",
		Redirects: config.Redirects{
			AfterLogin:    "/dashboard",
			AfterRegister: "/onboarding",
		},
		Pages: config.Pages{
			Login:    "/login",
			Register: "/register",
		},
	}
	authSvc, err := service.NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	if err := ensureMigrated(authSvc.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return New(authSvc, "auth")
}

func TestFormHandler_RegisterAndLoginFlow(t *testing.T) {
	h := setupFormTestHandler(t)
	email := util.UniqueEmail("formuser")
	password := "password123"

	// 1. Form Register
	t.Run("FormRegister", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)
		form.Add("password_confirm", password)

		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected status 302, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if location != "/onboarding" {
			t.Errorf("expected redirect to /onboarding, got %s", location)
		}

		// Check for session cookie
		cookie := w.Result().Cookies()
		found := false
		for _, c := range cookie {
			if c.Name == "ezauthsess" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected session cookie to be set")
		}
	})

	// 2. Form Login
	t.Run("FormLogin", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)

		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected status 302, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if location != "/dashboard" {
			t.Errorf("expected redirect to /dashboard, got %s", location)
		}

		// Verify cookie is set
		cookies := w.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == "ezauthsess" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected session cookie")
		}
	})

	// 3. Form Logout
	t.Run("FormLogout", func(t *testing.T) {
		// First login to get a valid session
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)
		loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		loginW := httptest.NewRecorder()
		h.ServeHTTP(loginW, loginReq)

		sessionCookie := loginW.Result().Cookies()[0] // Assuming first one is the session

		// Now logout
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.AddCookie(sessionCookie)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected status 302, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		if location != "/login" {
			t.Errorf("expected redirect to /login, got %s", location)
		}

		// Verify session cookie is cleared/expired
		// Note: scs might just overwrite it or set empty value.
		// Ideally we check validity, but just ensuring the flow works is enough here.
	})
}

func TestFormHandler_RegisterWithMetadata(t *testing.T) {
	h := setupFormTestHandler(t)
	email := util.UniqueEmail("metauser")
	password := "password123"

	t.Run("RegisterWithMetaFields", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)
		form.Add("password_confirm", password)
		form.Add("meta_theme", "dark")
		form.Add("meta_newsletter", "true")

		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected status 302, got %d", w.Code)
		}

		// Verify user metadata in DB
		user, err := h.svc.Repo.UserGetByEmail(req.Context(), email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}

		if user.UserMetadata == nil {
			t.Fatal("expected user metadata to be set")
		}

		if val, ok := user.UserMetadata["theme"]; !ok || val != "dark" {
			t.Errorf("expected metadata theme=dark, got %v", val)
		}
		if val, ok := user.UserMetadata["newsletter"]; !ok || val != "true" {
			t.Errorf("expected metadata newsletter=true, got %v", val)
		}
	})
}

func TestFormHandler_RegisterMismatchPasswords(t *testing.T) {
	h := setupFormTestHandler(t)
	email := util.UniqueEmail("mismatch")
	password := "password123"

	t.Run("RegisterMismatchPasswords", func(t *testing.T) {
		form := url.Values{}
		form.Add("email", email)
		form.Add("password", password)
		form.Add("password_confirm", "differentpassword")

		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Errorf("expected status 302, got %d", w.Code)
		}

		location := w.Header().Get("Location")
		// With flash messages, we expect a clean redirect URL (no error= query param)
		if location != "/register" {
			t.Errorf("expected redirect to /register, got %s", location)
		}
	})
}

func formRegister(t *testing.T, h *Handler, email, password string) {
	t.Helper()
	form := url.Values{}
	form.Add("email", email)
	form.Add("password", password)
	form.Add("password_confirm", password)

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("register failed for %s: expected 302, got %d", email, w.Code)
	}
}

func formLogin(t *testing.T, h *Handler, email, password string) *http.Cookie {
	t.Helper()
	form := url.Values{}
	form.Add("email", email)
	form.Add("password", password)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("login failed for %s: expected 302, got %d", email, w.Code)
	}
	return w.Result().Cookies()[0]
}

// formSessionUser loads the session referenced by cookie and resolves the user it
// currently authenticates as, without going through an HTTP round trip.
func formSessionUser(t *testing.T, h *Handler, cookie *http.Cookie) *models.User {
	t.Helper()
	ctx, err := h.Session.Load(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("failed to load session: %v", err)
	}
	user, err := h.GetSessionUser(ctx)
	if err != nil {
		t.Fatalf("failed to resolve session user: %v", err)
	}
	return user
}

func TestFormHandler_ImpersonationSwapBack(t *testing.T) {
	h := setupFormTestHandler(t)
	password := "password123"

	adminEmail := util.UniqueEmail("form-impersonate-admin")
	targetEmail := util.UniqueEmail("form-impersonate-target")
	formRegister(t, h, adminEmail, password)
	formRegister(t, h, targetEmail, password)

	ctx := context.Background()
	admin, err := h.svc.Repo.UserGetByEmail(ctx, adminEmail)
	if err != nil {
		t.Fatalf("failed to fetch admin: %v", err)
	}
	target, err := h.svc.Repo.UserGetByEmail(ctx, targetEmail)
	if err != nil {
		t.Fatalf("failed to fetch target: %v", err)
	}

	admin.Roles = "admin"
	if _, err := h.svc.Repo.UserUpdate(ctx, admin); err != nil {
		t.Fatalf("failed to promote admin: %v", err)
	}

	adminCookie := formLogin(t, h, adminEmail, password)
	if got := formSessionUser(t, h, adminCookie); got.ID != admin.ID {
		t.Fatalf("expected admin session before impersonation, got %s", got.Email)
	}

	var impersonatedCookie *http.Cookie

	t.Run("FormImpersonate", func(t *testing.T) {
		form := url.Values{}
		form.Add("target_user_id", target.ID)
		req := httptest.NewRequest(http.MethodPost, "/auth/impersonate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(adminCookie)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected status 302, got %d", w.Code)
		}
		if len(w.Result().Cookies()) == 0 {
			t.Fatal("expected a session cookie to be set")
		}
		impersonatedCookie = w.Result().Cookies()[0]

		if got := formSessionUser(t, h, impersonatedCookie); got.ID != target.ID {
			t.Fatalf("expected session to resolve to target after impersonate, got %s", got.Email)
		}
	})

	t.Run("reject double impersonation", func(t *testing.T) {
		form := url.Values{}
		form.Add("target_user_id", admin.ID)
		req := httptest.NewRequest(http.MethodPost, "/auth/impersonate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(impersonatedCookie)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected status 302, got %d", w.Code)
		}
		// Session must still resolve to the target, not have started a nested impersonation.
		if got := formSessionUser(t, h, impersonatedCookie); got.ID != target.ID {
			t.Fatalf("expected session to still resolve to target after rejected double impersonation, got %s", got.Email)
		}
	})

	t.Run("reject impersonation with no session", func(t *testing.T) {
		form := url.Values{}
		form.Add("target_user_id", target.ID)
		req := httptest.NewRequest(http.MethodPost, "/auth/impersonate", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected status 302, got %d", w.Code)
		}
		location := w.Header().Get("Location")
		if location != h.svc.Cfg.Pages.Login {
			t.Errorf("expected redirect to login page, got %s", location)
		}
	})

	t.Run("FormStopImpersonation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/impersonate/stop", nil)
		req.AddCookie(impersonatedCookie)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("expected status 302, got %d: %s", w.Code, w.Body.String())
		}
		if len(w.Result().Cookies()) == 0 {
			t.Fatal("expected a session cookie to be set")
		}
		restoredCookie := w.Result().Cookies()[0]

		if got := formSessionUser(t, h, restoredCookie); got.ID != admin.ID {
			t.Fatalf("expected session to resolve back to admin after stop, got %s", got.Email)
		}
	})
}
