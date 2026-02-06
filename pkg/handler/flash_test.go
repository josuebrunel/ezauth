package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"

	_ "modernc.org/sqlite"
)

func setupFlashTestHandler(t *testing.T) *Handler {
	dialect, dsn := util.GetTestDBConfig("flash_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		Addr:      ":8080",
		ApiKey:    "test-api-key",
		Pages: config.Pages{
			Login:    "/login",
			Register: "/register",
		},
	}

	authSvc, err := service.NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	return New(authSvc, "auth")
}

func TestFlash_SetAndGet(t *testing.T) {
	h := setupFlashTestHandler(t)

	// Create a request to pass through session middleware
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	// Wrap the test in session middleware
	h.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Set flash messages
		h.SetFlash(ctx, "error", "test error")
		h.SetFlash(ctx, "success", "test success")

		// Verify GetErrorMessage retrieves and clears
		if got := h.GetErrorMessage(ctx); got != "test error" {
			t.Errorf("GetErrorMessage() = %q, want %q", got, "test error")
		}

		// Verify GetSuccessMessage retrieves and clears
		if got := h.GetSuccessMessage(ctx); got != "test success" {
			t.Errorf("GetSuccessMessage() = %q, want %q", got, "test success")
		}
	})).ServeHTTP(w, req)
}

func TestFlash_AutoClear(t *testing.T) {
	h := setupFlashTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Set and get once
		h.SetFlash(ctx, "error", "one time message")
		_ = h.GetErrorMessage(ctx)

		// Second get should return empty string
		if got := h.GetErrorMessage(ctx); got != "" {
			t.Errorf("GetErrorMessage() after clear = %q, want empty string", got)
		}
	})).ServeHTTP(w, req)
}

func TestFlash_GetFlashGeneric(t *testing.T) {
	h := setupFlashTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	h.Session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Use generic SetFlash/GetFlash with custom key
		h.SetFlash(ctx, "custom_key", "custom value")

		if got := h.GetFlash(ctx, "custom_key"); got != "custom value" {
			t.Errorf("GetFlash(custom_key) = %q, want %q", got, "custom value")
		}

		// Should be cleared
		if got := h.GetFlash(ctx, "custom_key"); got != "" {
			t.Errorf("GetFlash(custom_key) after clear = %q, want empty string", got)
		}
	})).ServeHTTP(w, req)
}
