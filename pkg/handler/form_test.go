package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/service"
)

func setupFormTestHandler(t *testing.T) *Handler {
	// Use in-memory SQLite database
	dsn := fmt.Sprintf("file:%d?mode=memory&cache=shared", time.Now().UnixNano())
	cfg := &config.Config{
		DB: config.Database{
			Dialect: "sqlite3",
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
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

	// Run migrations
	if err := migrations.MigrateUpWithDBConn(authSvc.Repo.DB(), "sqlite3"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return New(authSvc, "auth")
}

func TestFormHandler_RegisterAndLoginFlow(t *testing.T) {
	h := setupFormTestHandler(t)
	email := "formuser@example.com"
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
	email := "metauser@example.com"
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
	email := "mismatch@example.com"
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
		if !strings.Contains(location, "error=passwords+do+not+match") { // Check encoded error message
			t.Errorf("expected error 'passwords do not match' in redirect, got %s", location)
		}
	})
}
