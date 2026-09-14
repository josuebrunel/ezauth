package handler

import (
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

// loginFormRequest builds a POST /auth/login request against h with the
// given extra headers. httptest.NewRequest defaults req.Host to
// "example.com" for a path-only target, which is what the Origin-match
// cases below rely on. The body content doesn't matter for these tests --
// the CSRF middleware runs before FormLogin ever looks at it -- only
// whether the request clears the CSRF layer (any status other than 403)
// or not.
func loginFormRequest(headers map[string]string) *http.Request {
	form := url.Values{}
	form.Add("email", "someone@example.com")
	form.Add("password", "wrong-password")

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestCSRF_CrossSiteRejected(t *testing.T) {
	h := setupFormTestHandler(t)

	req := loginFormRequest(map[string]string{"Sec-Fetch-Site": "cross-site"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a cross-site Sec-Fetch-Site request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCSRF_OriginMismatchRejected(t *testing.T) {
	h := setupFormTestHandler(t)

	// No Sec-Fetch-Site header (as if from an older browser), but an Origin
	// that doesn't match the request's Host ("example.com").
	req := loginFormRequest(map[string]string{"Origin": "https://evil.example"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a mismatched Origin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCSRF_SameOriginAllowed(t *testing.T) {
	h := setupFormTestHandler(t)

	req := loginFormRequest(map[string]string{"Sec-Fetch-Site": "same-origin"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected a same-origin request to clear the CSRF layer, got 403: %s", w.Body.String())
	}
}

func TestCSRF_OriginMatchingHostAllowed(t *testing.T) {
	h := setupFormTestHandler(t)

	// No Sec-Fetch-Site header, but Origin's host matches the request's
	// Host ("example.com") -- the scheme is irrelevant to this check.
	req := loginFormRequest(map[string]string{"Origin": "http://example.com"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected a matching Origin to clear the CSRF layer, got 403: %s", w.Body.String())
	}
}

// TestCSRF_NoHeadersAllowed documents the behavior the rest of this
// package's Form-handler tests have implicitly relied on all along:
// filippo.io/csrf treats a request with neither Sec-Fetch-Site nor Origin
// as same-origin or non-browser, and allows it. httptest.NewRequest sets
// neither header by default, which is why the existing suite has never
// exercised the CSRF layer's rejecting path.
func TestCSRF_NoHeadersAllowed(t *testing.T) {
	h := setupFormTestHandler(t)

	req := loginFormRequest(nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected a request with no Sec-Fetch-Site/Origin headers to clear the CSRF layer, got 403: %s", w.Body.String())
	}
}

// TestCSRF_SafeMethodsAlwaysAllowed proves GET/HEAD/OPTIONS bypass the
// cross-origin check entirely, regardless of Sec-Fetch-Site -- GET /auth/csrf
// is the concrete route consumers hit for a token (see below).
func TestCSRF_SafeMethodsAlwaysAllowed(t *testing.T) {
	h := setupFormTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected safe methods to bypass CSRF checks, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCSRF_TokenEndpoint(t *testing.T) {
	h := setupFormTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-CSRF-Token") == "" {
		t.Error("expected X-CSRF-Token response header to be set")
	}
	if !strings.Contains(w.Body.String(), "csrf_token") {
		t.Errorf("expected a csrf_token field in the JSON body, got %s", w.Body.String())
	}
}

// TestCSRF_TrustedOriginBypassesCrossSiteCheck proves CSRFTrustedOrigins
// (wired into csrf.TrustedOrigins) exempts a configured origin from the
// cross-origin check even when Sec-Fetch-Site says cross-site -- the gap
// a frontend served from a different origin than ezauth would otherwise
// hit -- while an origin not on the list is still rejected.
func TestCSRF_TrustedOriginBypassesCrossSiteCheck(t *testing.T) {
	dialect, dsn := util.GetTestDBConfig("csrf_trusted_origin_test")
	cfg := &config.Config{
		DB:                 config.Database{Dialect: dialect, DSN: dsn},
		JWTSecret:          "test-secret-0123456789-0123456789",
		Hashing:            config.Hashing{BcryptCost: 4},
		CSRFTrustedOrigins: "https://trusted.example",
		Pages:              config.Pages{Login: "/login"},
	}
	authSvc, err := service.NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := ensureMigrated(authSvc.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	h := New(authSvc, "auth")

	t.Run("trusted origin bypasses the cross-site check", func(t *testing.T) {
		req := loginFormRequest(map[string]string{
			"Sec-Fetch-Site": "cross-site",
			"Origin":         "https://trusted.example",
		})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code == http.StatusForbidden {
			t.Fatalf("expected a trusted Origin to bypass the CSRF check, got 403: %s", w.Body.String())
		}
	})

	t.Run("an origin not on the trusted list is still rejected", func(t *testing.T) {
		req := loginFormRequest(map[string]string{
			"Sec-Fetch-Site": "cross-site",
			"Origin":         "https://untrusted.example",
		})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected an untrusted Origin to still be rejected, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// TestCSRF_JSONAPINotProtected documents that the CSRF middleware only
// wraps the Form-handler route group (see handler.New) -- the JSON API,
// gated by APIKeyMiddleware instead of cookies, is deliberately outside
// it, since CSRF is a browser/cookie problem that doesn't apply to
// API-key/Bearer-authenticated clients.
func TestCSRF_JSONAPINotProtected(t *testing.T) {
	h := setupFormTestHandler(t)

	form := url.Values{}
	form.Add("email", "someone@example.com")
	form.Add("password", "wrong-password")
	req := httptest.NewRequest(http.MethodPost, "/auth/api/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected the JSON API to be unaffected by the CSRF layer, got 403: %s", w.Body.String())
	}
}
