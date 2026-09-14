package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSwaggerRoute(t *testing.T) {
	t.Run("open by default, matching every prior release", func(t *testing.T) {
		h := newAdminAuthzTestHandler(t)
		req := httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == http.StatusNotFound {
			t.Fatalf("expected /swagger/* to be registered by default, got 404")
		}
	})

	t.Run("WithSwaggerAuth(nil) removes the route entirely", func(t *testing.T) {
		h := newAdminAuthzTestHandler(t, WithSwaggerAuth(nil))
		req := httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 with the route removed, got %d", w.Code)
		}
	})

	t.Run("WithSwaggerAuth(mw) gates the route with the given middleware", func(t *testing.T) {
		blocked := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			})
		}
		h := newAdminAuthzTestHandler(t, WithSwaggerAuth(blocked))
		req := httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected the custom middleware to run and return 403, got %d", w.Code)
		}
	})
}
