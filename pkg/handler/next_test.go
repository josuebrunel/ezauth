package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/pquerna/otp/totp"
)

// sessionCookie returns the ezauth session cookie set by w, or nil.
func sessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == "ezauthsess" {
			return c
		}
	}
	return nil
}

// protectedApp mounts h.LoginRequiredMiddleware on an app route, the way a
// consuming application does, behind the session middleware.
func protectedApp(h *Handler) http.Handler {
	return h.Session.LoadAndSave(h.LoginRequiredMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
}

// visitLoggedOut asks for path while logged out and returns the session
// cookie carrying the remembered page.
func visitLoggedOut(t *testing.T, h *Handler, path string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	protectedApp(h).ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 for a logged-out visit to %s, got %d", path, w.Code)
	}
	want := "/login?next=" + url.QueryEscape(path)
	if loc := w.Header().Get("Location"); loc != want {
		t.Fatalf("expected redirect to %q, got %q", want, loc)
	}
	c := sessionCookie(w)
	if c == nil {
		t.Fatal("expected a session cookie remembering the page")
	}
	return c
}

func postForm(h *Handler, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestLoginRedirectsBackToNext(t *testing.T) {
	h := setupFormTestHandler(t)
	password := "password123"
	email := util.UniqueEmail("next-user")
	formRegister(t, h, email, password)
	creds := url.Values{"email": {email}, "password": {password}}

	t.Run("page remembered by LoginRequiredMiddleware", func(t *testing.T) {
		cookie := visitLoggedOut(t, h, "/dashboard/settings?tab=billing")
		w := postForm(h, "/auth/login", creds, cookie)
		if loc := w.Header().Get("Location"); loc != "/dashboard/settings?tab=billing" {
			t.Fatalf("expected redirect back to the page asked for, got %q", loc)
		}

		// It's used once: the next login goes to AfterLogin.
		w = postForm(h, "/auth/login", creds, sessionCookie(w))
		if loc := w.Header().Get("Location"); loc != h.svc.Cfg.Redirects.AfterLogin {
			t.Errorf("expected next to be cleared after use, got %q", loc)
		}
	})

	t.Run("explicit next wins over the remembered one", func(t *testing.T) {
		cookie := visitLoggedOut(t, h, "/remembered")
		form := url.Values{"email": {email}, "password": {password}, "next": {"/explicit"}}
		w := postForm(h, "/auth/login", form, cookie)
		if loc := w.Header().Get("Location"); loc != "/explicit" {
			t.Errorf("expected redirect to /explicit, got %q", loc)
		}
	})

	t.Run("remembered across a failed attempt", func(t *testing.T) {
		cookie := visitLoggedOut(t, h, "/reports")
		bad := url.Values{"email": {email}, "password": {"wrong-password"}}
		w := postForm(h, "/auth/login", bad, cookie)
		if loc := w.Header().Get("Location"); loc != h.svc.Cfg.Pages.Login {
			t.Fatalf("expected a failed login to go back to the login page, got %q", loc)
		}
		if c := sessionCookie(w); c != nil {
			cookie = c
		}
		w = postForm(h, "/auth/login", creds, cookie)
		if loc := w.Header().Get("Location"); loc != "/reports" {
			t.Errorf("expected redirect to /reports, got %q", loc)
		}
	})

	t.Run("unsafe next is ignored", func(t *testing.T) {
		for _, next := range []string{"//evil.com", "https://evil.com/x", "/\\evil.com", "dashboard"} {
			form := url.Values{"email": {email}, "password": {password}, "next": {next}}
			w := postForm(h, "/auth/login", form, nil)
			if loc := w.Header().Get("Location"); loc != h.svc.Cfg.Redirects.AfterLogin {
				t.Errorf("next=%q: expected redirect to AfterLogin, got %q", next, loc)
			}
		}
	})

	t.Run("JSON and HTMX requests aren't remembered", func(t *testing.T) {
		jsonReq := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
		jsonReq.Header.Set("Accept", "application/json")
		htmxReq := httptest.NewRequest(http.MethodGet, "/fragment", nil)
		htmxReq.Header.Set("HX-Request", "true")
		for _, req := range []*http.Request{jsonReq, htmxReq} {
			w := httptest.NewRecorder()
			protectedApp(h).ServeHTTP(w, req)
			if c := sessionCookie(w); c != nil {
				ctx, err := h.Session.Load(context.Background(), c.Value)
				if err != nil {
					t.Fatalf("failed to load session: %v", err)
				}
				if got := h.Session.GetString(ctx, sessionNextKey); got != "" {
					t.Errorf("%s: expected nothing remembered, got %q", req.URL, got)
				}
			}
		}
	})

}

func TestMFALoginRedirectsBackToNext(t *testing.T) {
	h := setupFormTestHandler(t)
	h.svc.Cfg.Pages.MFAVerify = "/mfa"
	password := "password123"
	email := util.UniqueEmail("next-mfa")
	formRegister(t, h, email, password)

	ctx := context.Background()
	user, err := h.svc.Repo.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user: %v", err)
	}
	enroll, err := h.svc.MFAEnroll(ctx, user)
	if err != nil {
		t.Fatalf("MFAEnroll failed: %v", err)
	}
	code, err := totp.GenerateCode(enroll.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}
	if _, err := h.svc.MFAConfirm(ctx, user, code); err != nil {
		t.Fatalf("MFAConfirm failed: %v", err)
	}

	cookie := visitLoggedOut(t, h, "/billing")
	w := postForm(h, "/auth/login", url.Values{"email": {email}, "password": {password}}, cookie)
	if loc := w.Header().Get("Location"); loc != h.svc.Cfg.Pages.MFAVerify {
		t.Fatalf("expected the MFA step, got %q", loc)
	}
	if c := sessionCookie(w); c != nil {
		cookie = c
	}

	code, err = totp.GenerateCode(enroll.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate totp code: %v", err)
	}
	w = postForm(h, "/auth/mfa/login/verify", url.Values{"code": {code}}, cookie)
	if loc := w.Header().Get("Location"); loc != "/billing" {
		t.Errorf("expected redirect to /billing after MFA, got %q (%d)", loc, w.Code)
	}
}

func TestPasswordlessLoginRedirectsBackToNext(t *testing.T) {
	h := setupFormTestHandler(t)
	email := util.UniqueEmail("next-passwordless")

	w := postForm(h, "/auth/passwordless/request", url.Values{"email": {email}, "next": {"/inbox"}}, nil)
	cookie := sessionCookie(w)
	if cookie == nil {
		t.Fatal("expected a session cookie remembering next")
	}

	mockMailer := h.svc.Mailer.(*service.MockMailer)
	sentBody := mockMailer.SentEmails[len(mockMailer.SentEmails)-1]["body"]
	tokenStart := strings.Index(sentBody, "token=")
	if tokenStart == -1 {
		t.Fatalf("could not find token in email body: %s", sentBody)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/passwordless/login?token="+url.QueryEscape(sentBody[tokenStart+len("token="):]), nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if loc := w.Header().Get("Location"); loc != "/inbox" {
		t.Errorf("expected redirect to /inbox, got %q (%d)", loc, w.Code)
	}
}
