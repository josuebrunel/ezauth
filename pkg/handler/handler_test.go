package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

func setupTestHandler(t *testing.T) *Handler {
	dialect, dsn := util.GetTestDBConfig("handler_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
		Addr:      ":8080",
		ApiKey:    "test-api-key",
		EmailTemplates: config.EmailTemplates{
			PasswordlessSubject:  "Magic Link Login",
			PasswordlessBody:     "Click the following link to login: {{.Link}}",
			PasswordResetSubject: "Password Reset Request",
			PasswordResetBody:    "Click the following link to reset your password: {{.Link}}",
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

// Helper struct to decode responses in tests
type testResponse[T any] struct {
	Error any `json:"error"`
	Data  T   `json:"data"`
}

func TestHandler_RegisterAndLoginFlow(t *testing.T) {
	h := setupTestHandler(t)

	email := util.UniqueEmail("handler")
	password := "password123"
	var accessToken string
	var refreshToken string

	// 1. Register
	t.Run("Register", func(t *testing.T) {
		reqBody := map[string]any{
			"email":    email,
			"username": "handler_user",
			"password": password,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d: %s", w.Code, w.Body.String())
		}

		var resp testResponse[service.TokenResponse]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp.Data.AccessToken == "" {
			t.Error("expected access token to be present")
		}
		accessToken = resp.Data.AccessToken
		refreshToken = resp.Data.RefreshToken

		// Verify username was saved
		fetchedUser, err := h.svc.Repo.UserGetByUsername(context.Background(), "handler_user")
		if err != nil {
			t.Fatalf("failed to fetch user by username: %v", err)
		}
		if fetchedUser.Email != email {
			t.Errorf("expected email %s, got %s", email, fetchedUser.Email)
		}
	})

	// 2. Login
	t.Run("Login", func(t *testing.T) {
		reqBody := map[string]any{
			"email":    email,
			"password": password,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp testResponse[service.TokenResponse]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Data.AccessToken == "" {
			t.Error("expected access token")
		}
	})

	// 3. UserInfo (Protected)
	t.Run("UserInfo", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp testResponse[models.User]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Data.Email != email {
			t.Errorf("expected email %s, got %s", email, resp.Data.Email)
		}
	})

	// 4. Refresh Token
	t.Run("RefreshToken", func(t *testing.T) {
		reqBody := map[string]string{
			"refresh_token": refreshToken,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/token/refresh", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp testResponse[service.TokenResponse]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Data.AccessToken == "" {
			t.Error("expected new access token")
		}
		// Update access token for subsequent tests if needed
		accessToken = resp.Data.AccessToken
	})

	// 5. Logout
	t.Run("Logout", func(t *testing.T) {
		reqBody := map[string]string{
			"refresh_token": refreshToken,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/logout", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	// 6. Delete User
	t.Run("DeleteUser", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/auth/api/user", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// TestHandler_Login_DoesNotLeakAccountExistenceOrLockState proves the JSON
// API's Login always returns the same generic message regardless of cause
// (no such account, wrong password, or a real account that's locked/
// disabled) -- ErrAccountLocked/ErrAccountDisabled only ever apply to an
// account that exists, so surfacing them verbatim would let an anonymous
// caller distinguish "no such account" from "account exists but is locked",
// an account-enumeration side channel.
func TestHandler_Login_DoesNotLeakAccountExistenceOrLockState(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	email := util.UniqueEmail("lockleak")
	password := "password123"
	if _, err := h.svc.UserCreate(ctx, &service.RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}
	user, err := h.svc.Repo.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("UserGetByEmail failed: %v", err)
	}
	if _, err := h.svc.Repo.UserSetLockoutState(ctx, user.ID, 0, nil, false); err != nil {
		t.Fatalf("UserSetLockoutState failed: %v", err)
	}

	login := func(t *testing.T, loginEmail, loginPassword string) (int, string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"email": loginEmail, "password": loginPassword})
		req := httptest.NewRequest(http.MethodPost, "/auth/api/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		var resp testResponse[string]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		errMsg, _ := resp.Error.(string)
		return w.Code, errMsg
	}

	lockedStatus, lockedMsg := login(t, email, password)
	if lockedStatus != http.StatusUnauthorized {
		t.Errorf("expected 401 for a locked account, got %d", lockedStatus)
	}
	if strings.Contains(strings.ToLower(lockedMsg), "lock") || strings.Contains(strings.ToLower(lockedMsg), "disabl") {
		t.Errorf("expected a generic message for a locked account, got %q", lockedMsg)
	}

	unknownStatus, unknownMsg := login(t, util.UniqueEmail("nosuchaccount"), password)
	if unknownStatus != http.StatusUnauthorized {
		t.Errorf("expected 401 for an unknown account, got %d", unknownStatus)
	}

	wrongPassStatus, wrongPassMsg := login(t, email, "wrong-password")
	if wrongPassStatus != http.StatusUnauthorized {
		t.Errorf("expected 401 for a wrong password, got %d", wrongPassStatus)
	}

	if lockedStatus != unknownStatus || lockedMsg != unknownMsg {
		t.Errorf("expected identical status/message for locked vs unknown account, got (%d, %q) vs (%d, %q)", lockedStatus, lockedMsg, unknownStatus, unknownMsg)
	}
	if lockedStatus != wrongPassStatus || lockedMsg != wrongPassMsg {
		t.Errorf("expected identical status/message for locked vs wrong-password, got (%d, %q) vs (%d, %q)", lockedStatus, lockedMsg, wrongPassStatus, wrongPassMsg)
	}
}

func TestHandler_ApiKeyFromDB(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()

	// Create a user and an API key token
	user, err := h.svc.Repo.UserCreate(ctx, &models.User{
		Email: util.UniqueEmail("apikey"),
	})
	if err != nil {
		t.Fatal(err)
	}

	apiKeyToken := util.Must(util.RandomString(16))
	_, err = h.svc.Repo.TokenCreate(ctx, &models.Token{
		UserID:    user.ID,
		Token:     util.HashToken(apiKeyToken),
		TokenType: models.TokenTypeApiKey,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Now make a request with this API Key
	// Using /auth/api/register with empty body. If auth passes, it returns 400. If auth fails, 401.
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer([]byte(`{}`)))
	req.Header.Set("X-API-Key", apiKeyToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Error("expected authorized request with DB api key, got 401")
	}
}

func TestHandler_PasswordReset(t *testing.T) {
	h := setupTestHandler(t)
	email := util.UniqueEmail("reset")
	password := "old-password"

	// 1. Register user
	reqBody := map[string]any{"email": email, "password": password}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	h.ServeHTTP(httptest.NewRecorder(), req)

	// 2. Request reset
	reqBody = map[string]any{"email": email}
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/api/password-reset/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 3. Get token from mock mailer
	mockMailer := h.svc.Mailer.(*service.MockMailer)
	sentBody := mockMailer.SentEmails[0]["body"]
	tokenStart := strings.Index(sentBody, "token=")
	if tokenStart == -1 {
		t.Fatalf("could not find token in email body: %s", sentBody)
	}
	tokenValue := sentBody[tokenStart+6:]

	// 4. Confirm reset
	newPassword := "new-password"
	reqBody = map[string]any{"token": tokenValue, "password": newPassword}
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/api/password-reset/confirm", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Login with new password
	reqBody = map[string]any{"email": email, "password": newPassword}
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after password reset, got %d", w.Code)
	}
}

func TestHandler_Passwordless(t *testing.T) {
	h := setupTestHandler(t)
	email := util.UniqueEmail("magic")

	// 1. Request magic link
	reqBody := map[string]any{"email": email}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/passwordless/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. Get token from mock mailer
	mockMailer := h.svc.Mailer.(*service.MockMailer)
	sentBody := mockMailer.SentEmails[0]["body"]
	tokenStart := strings.Index(sentBody, "token=")
	if tokenStart == -1 {
		t.Fatalf("could not find token in email body: %s", sentBody)
	}
	tokenValue := sentBody[tokenStart+6:]

	// 3. Login with magic link
	req = httptest.NewRequest(http.MethodGet, "/auth/api/passwordless/login?token="+tokenValue, nil)
	req.Header.Set("X-API-Key", "test-api-key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp testResponse[service.TokenResponse]
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.AccessToken == "" {
		t.Error("expected access token")
	}
}

// TestHandler_PasswordlessLogin_AcceptsPOSTJSONBody proves the JSON API's
// PasswordlessLogin accepts the token in a POST body, not just the GET
// query string -- the safer option, since a query-string token lands in
// access logs, browser history, and Referer headers (see #208). Also
// confirms the Referrer-Policy: no-referrer response header.
func TestHandler_PasswordlessLogin_AcceptsPOSTJSONBody(t *testing.T) {
	h := setupTestHandler(t)
	email := util.UniqueEmail("magic-post")

	reqBody := map[string]any{"email": email}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/passwordless/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	mockMailer := h.svc.Mailer.(*service.MockMailer)
	sentBody := mockMailer.SentEmails[len(mockMailer.SentEmails)-1]["body"]
	tokenStart := strings.Index(sentBody, "token=")
	if tokenStart == -1 {
		t.Fatalf("could not find token in email body: %s", sentBody)
	}
	tokenValue := sentBody[tokenStart+6:]

	loginBody, _ := json.Marshal(map[string]string{"token": tokenValue})
	req = httptest.NewRequest(http.MethodPost, "/auth/api/passwordless/login", bytes.NewBuffer(loginBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for POST passwordless login, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("expected Referrer-Policy: no-referrer, got %q", got)
	}
	var resp testResponse[service.TokenResponse]
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.AccessToken == "" {
		t.Error("expected access token")
	}
}

// TestHandler_EmailChangeConfirm_AcceptsPOSTJSONBody mirrors
// TestHandler_PasswordlessLogin_AcceptsPOSTJSONBody for the email-change
// confirmation flow.
func TestHandler_EmailChangeConfirm_AcceptsPOSTJSONBody(t *testing.T) {
	h := setupTestHandler(t)
	ctx := context.Background()
	h.svc.Cfg.EmailTemplates.EmailChangeSubject = "Confirm your new email address"
	h.svc.Cfg.EmailTemplates.EmailChangeBody = "Click the following link to confirm your new email address: {{.Link}}"

	password := "securepass123"
	user, err := h.svc.UserCreate(ctx, &service.RequestBasicAuth{Email: util.UniqueEmail("api-emailchange-post"), Password: password})
	if err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}
	newEmail := util.UniqueEmail("api-emailchange-post-new")
	if err := h.svc.EmailChangeRequest(ctx, user, service.RequestEmailChange{CurrentPassword: password, NewEmail: newEmail}); err != nil {
		t.Fatalf("EmailChangeRequest failed: %v", err)
	}

	mockMailer := h.svc.Mailer.(*service.MockMailer)
	var sentBody string
	for _, e := range mockMailer.SentEmails {
		if e["to"] == newEmail {
			sentBody = e["body"]
		}
	}
	tokenStart := strings.Index(sentBody, "token=")
	if tokenStart == -1 {
		t.Fatalf("could not find token in email body: %s", sentBody)
	}
	tokenValue := sentBody[tokenStart+6:]

	confirmBody, _ := json.Marshal(map[string]string{"token": tokenValue})
	req := httptest.NewRequest(http.MethodPost, "/auth/api/email-change/confirm", bytes.NewBuffer(confirmBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for POST email change confirm, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("expected Referrer-Policy: no-referrer, got %q", got)
	}

	updated, err := h.svc.Repo.UserGetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("UserGetByID failed: %v", err)
	}
	if updated.Email != newEmail {
		t.Errorf("expected email to be updated to %q, got %q", newEmail, updated.Email)
	}
}

// testHook records which hooks were called for test verification.
type testHook struct {
	service.DefaultHook
	calls []string
	mu    sync.Mutex

	// If set, BeforeUserCreated returns this error.
	beforeCreateErr error
	// If set, BeforeUserDeleted returns this error.
	beforeDeleteErr error
}

func (h *testHook) record(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, name)
}

func (h *testHook) BeforeUserCreated(ctx context.Context, user *models.User) error {
	h.record("BeforeUserCreated")
	return h.beforeCreateErr
}

func (h *testHook) AfterUserCreated(ctx context.Context, user *models.User) error {
	h.record("AfterUserCreated")
	return nil
}

func (h *testHook) BeforeUserDeleted(ctx context.Context, user *models.User) error {
	h.record("BeforeUserDeleted")
	return h.beforeDeleteErr
}

func (h *testHook) AfterUserDeleted(ctx context.Context, user *models.User) error {
	h.record("AfterUserDeleted")
	return nil
}

func (h *testHook) AfterUserSignedIn(ctx context.Context, user *models.User) error {
	h.record("AfterUserSignedIn")
	return nil
}

func (h *testHook) AfterUserSignedOut(ctx context.Context, user *models.User) error {
	h.record("AfterUserSignedOut")
	return nil
}

func (h *testHook) AfterPasswordResetRequested(ctx context.Context, user *models.User) error {
	h.record("AfterPasswordResetRequested")
	return nil
}

func (h *testHook) AfterPasswordResetConfirmed(ctx context.Context, user *models.User) error {
	h.record("AfterPasswordResetConfirmed")
	return nil
}

func (h *testHook) AfterImpersonationStarted(ctx context.Context, admin, target *models.User) error {
	h.record("AfterImpersonationStarted")
	return nil
}

func (h *testHook) AfterImpersonationEnded(ctx context.Context, admin, target *models.User) error {
	h.record("AfterImpersonationEnded")
	return nil
}

func TestHandler_Hooks_DefaultNeverPanics(t *testing.T) {
	// The default hook is used by the handler setup, so the existing
	// TestHandler_RegisterAndLoginFlow already exercises DefaultHook.
	// This test verifies it explicitly.
	h := setupTestHandler(t)
	email := util.UniqueEmail("default-hook")
	password := "password123"

	// Register
	reqBody := map[string]any{"email": email, "password": password}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
}

func TestHandler_Hooks_BeforeUserCreated_AbortsRegistration(t *testing.T) {
	h := setupTestHandler(t)

	hook := &testHook{beforeCreateErr: errors.New("banned domain")}
	h.svc.Hook = hook

	email := util.UniqueEmail("banned")
	reqBody := map[string]any{"email": email, "password": "password123"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp testResponse[any]
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error == nil {
		t.Fatal("expected error message")
	}

	// Verify the user was NOT created
	_, err := h.svc.Repo.UserGetByEmail(context.Background(), email)
	if err == nil {
		t.Error("expected user NOT to exist after hook aborted registration")
	}
}

func TestHandler_Hooks_AfterUserSignedInCalled(t *testing.T) {
	h := setupTestHandler(t)

	hook := &testHook{}
	h.svc.Hook = hook

	// Register first
	email := util.UniqueEmail("hook-signin")
	password := "password123"
	reqBody := map[string]any{"email": email, "password": password}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	h.ServeHTTP(httptest.NewRecorder(), req)

	// Login
	reqBody2 := map[string]any{"email": email, "password": password}
	body2, _ := json.Marshal(reqBody2)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/api/login", bytes.NewBuffer(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req2)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if !containsHookCall(hook.calls, "AfterUserSignedIn") {
		t.Errorf("expected AfterUserSignedIn to be called, got %v", hook.calls)
	}
}

func TestHandler_Hooks_BeforeUserDeleted_AbortsDeletion(t *testing.T) {
	h := setupTestHandler(t)

	hook := &testHook{beforeDeleteErr: errors.New("cannot delete")}
	h.svc.Hook = hook

	// Register first
	email := util.UniqueEmail("hook-delete")
	password := "password123"
	reqBody := map[string]any{"email": email, "password": password}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	var registerResp testResponse[service.TokenResponse]
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&registerResp)
	accessToken := registerResp.Data.AccessToken

	// Try to delete (should fail)
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/api/user", nil)
	delReq.Header.Set("Authorization", "Bearer "+accessToken)
	delReq.Header.Set("X-API-Key", "test-api-key")
	delW := httptest.NewRecorder()
	h.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", delW.Code, delW.Body.String())
	}

	// Verify the user still exists
	_, err := h.svc.Repo.UserGetByEmail(context.Background(), email)
	if err != nil {
		t.Error("expected user to still exist after hook aborted deletion")
	}
}

func TestHandler_Hooks_PasswordResetHooksCalled(t *testing.T) {
	h := setupTestHandler(t)

	hook := &testHook{}
	h.svc.Hook = hook

	// Register user
	email := util.UniqueEmail("hook-reset")
	reqBody := map[string]any{"email": email, "password": "password123"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	h.ServeHTTP(httptest.NewRecorder(), req)

	// Request password reset
	reqBody2 := map[string]any{"email": email}
	body2, _ := json.Marshal(reqBody2)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/api/password-reset/request", bytes.NewBuffer(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "test-api-key")
	h.ServeHTTP(httptest.NewRecorder(), req2)

	if !containsHookCall(hook.calls, "AfterPasswordResetRequested") {
		t.Errorf("expected AfterPasswordResetRequested to be called, got %v", hook.calls)
	}
}

func containsHookCall(calls []string, target string) bool {
	for _, c := range calls {
		if c == target {
			return true
		}
	}
	return false
}

func TestHandler_Unauthorized(t *testing.T) {
	h := setupTestHandler(t)

	t.Run("UserInfo_NoApiKey", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/userinfo", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("UserInfo_InvalidApiKey", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/userinfo", nil)
		req.Header.Set("X-API-Key", "invalid-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("UserInfo_NoToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/userinfo", nil)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("UserInfo_InvalidToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/userinfo", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})
}

// registerAndLogin registers a new user via the JSON API and returns the resulting
// tokens, for use as a test fixture.
func registerAndLogin(t *testing.T, h *Handler, emailPrefix string) (user *models.User, accessToken, refreshToken string) {
	t.Helper()
	email := util.UniqueEmail(emailPrefix)
	password := "password123"

	reqBody := map[string]any{"email": email, "password": password}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register failed: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp testResponse[service.TokenResponse]
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}

	u, err := h.svc.Repo.UserGetByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("failed to fetch registered user: %v", err)
	}

	return u, resp.Data.AccessToken, resp.Data.RefreshToken
}

// grantAdminRole grants userID the RBAC role h.svc.Cfg.AdminRole resolves to
// (default "admin"), creating the role first if it doesn't exist yet. This
// is what the default admin/RBAC/org/impersonation authorization gate (see
// WithAdminAuthz) checks via RequireRole -- a real deployment would grant it
// the same way (UserRoleGrant, or the ezauthapi create-admin CLI).
func grantAdminRole(t *testing.T, h *Handler, userID string) {
	t.Helper()
	ctx := context.Background()
	role := h.svc.Cfg.AdminRole
	if _, err := h.svc.RoleCreate(ctx, role, "test fixture admin role"); err != nil && err.Error() != "role already exists" {
		t.Fatalf("failed to create %q role: %v", role, err)
	}
	if err := h.svc.UserRoleGrant(ctx, "test-fixture", userID, role); err != nil {
		t.Fatalf("failed to grant %q role to %s: %v", role, userID, err)
	}
}

func TestHandler_Impersonation_JSON(t *testing.T) {
	h := setupTestHandler(t)
	hook := &testHook{}
	h.svc.Hook = hook

	admin, adminAccessToken, adminRefreshToken := registerAndLogin(t, h, "impersonate-admin")
	target, _, _ := registerAndLogin(t, h, "impersonate-target")

	// The default admin authorization gate (WithAdminAuthz) requires the
	// RBAC "admin" role -- grant it so this admin can actually reach
	// /impersonate. target gets it too: the "already impersonating" subtest
	// below calls /impersonate again *as target* (that's what an
	// impersonation access token's sub claim resolves to), and this test is
	// about that business-rule guard specifically, not the authz gate.
	grantAdminRole(t, h, admin.ID)
	grantAdminRole(t, h, target.ID)

	var impersonationAccessToken, impersonationRefreshToken string

	t.Run("Impersonate", func(t *testing.T) {
		reqBody := map[string]any{
			"target_user_id": target.ID,
			"refresh_token":  adminRefreshToken,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/impersonate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminAccessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp testResponse[ImpersonateResponse]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" {
			t.Fatal("expected new access/refresh tokens for the target user")
		}
		if resp.Data.OriginalAccessToken != adminAccessToken {
			t.Errorf("expected original_access_token to echo the admin's bearer token")
		}
		if resp.Data.OriginalRefreshToken != adminRefreshToken {
			t.Errorf("expected original_refresh_token to echo the submitted refresh token")
		}
		if resp.Data.ImpersonatorID != admin.ID {
			t.Errorf("expected impersonator_id %s, got %s", admin.ID, resp.Data.ImpersonatorID)
		}
		if resp.Data.TargetUserID != target.ID {
			t.Errorf("expected target_user_id %s, got %s", target.ID, resp.Data.TargetUserID)
		}

		impersonationAccessToken = resp.Data.AccessToken
		impersonationRefreshToken = resp.Data.RefreshToken

		if !containsHookCall(hook.calls, "AfterImpersonationStarted") {
			t.Errorf("expected AfterImpersonationStarted to be called, got %v", hook.calls)
		}
	})

	t.Run("UserInfo resolves target, not admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+impersonationAccessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp testResponse[models.User]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Data.Email != target.Email {
			t.Errorf("expected userinfo to resolve target %s, got %s", target.Email, resp.Data.Email)
		}
	})

	t.Run("cannot impersonate while already impersonating", func(t *testing.T) {
		reqBody := map[string]any{
			"target_user_id": admin.ID,
			"refresh_token":  impersonationRefreshToken,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/impersonate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+impersonationAccessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("a different admin's impersonation token cannot stop this one", func(t *testing.T) {
		otherAdmin, otherAdminAccessToken, otherAdminRefreshToken := registerAndLogin(t, h, "impersonate-other-admin")
		otherTarget, _, _ := registerAndLogin(t, h, "impersonate-other-target")
		grantAdminRole(t, h, otherAdmin.ID)
		// otherTarget also needs the admin role: the request below
		// authenticates with an impersonation access token, whose JWT "sub"
		// (what the admin-authz gate checks) is the target, not the actor.
		grantAdminRole(t, h, otherTarget.ID)

		reqBody := map[string]any{
			"target_user_id": otherTarget.ID,
			"refresh_token":  otherAdminRefreshToken,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/impersonate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+otherAdminAccessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp testResponse[ImpersonateResponse]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		otherImpersonationAccessToken := resp.Data.AccessToken

		// otherAdmin, authenticated via their OWN impersonation access token,
		// tries to stop the original admin's impersonation session by
		// submitting its refresh token value.
		stopBody := map[string]string{"refresh_token": impersonationRefreshToken}
		body, _ = json.Marshal(stopBody)
		req = httptest.NewRequest(http.MethodPost, "/auth/api/impersonate/stop", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+otherImpersonationAccessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 rejecting the wrong admin's stop attempt, got %d: %s", w.Code, w.Body.String())
		}
		// The original impersonation session must still be usable -- proven
		// by the "StopImpersonation" subtest below still succeeding with the
		// same, unmodified impersonationRefreshToken.
	})

	t.Run("StopImpersonation", func(t *testing.T) {
		reqBody := map[string]string{"refresh_token": impersonationRefreshToken}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/impersonate/stop", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+impersonationAccessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}

		if !containsHookCall(hook.calls, "AfterImpersonationEnded") {
			t.Errorf("expected AfterImpersonationEnded to be called, got %v", hook.calls)
		}
	})

	t.Run("refresh fails after stop", func(t *testing.T) {
		reqBody := map[string]string{"refresh_token": impersonationRefreshToken}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/token/refresh", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 for revoked impersonation token, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("no bearer token rejected", func(t *testing.T) {
		reqBody := map[string]any{"target_user_id": target.ID, "refresh_token": adminRefreshToken}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/impersonate", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})
}

func TestHandlerRun_GracefulShutdown(t *testing.T) {
	h := setupTestHandler(t)
	h.svc.Cfg.Addr = "127.0.0.1:0"

	done := make(chan struct{})
	go func() {
		h.Run()
		close(done)
	}()

	// Give Run()'s goroutine a moment to call ListenAndServe.
	time.Sleep(100 * time.Millisecond)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("failed to send SIGINT: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after SIGINT within the shutdown timeout")
	}
}

func TestHandler_RejectsOversizedRequestBody(t *testing.T) {
	h := setupTestHandler(t)

	oversized := bytes.Repeat([]byte("a"), defaultMaxBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for an oversized body (decode fails once MaxBytesReader's limit is hit), got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_SecureCookies(t *testing.T) {
	newHandler := func(t *testing.T, baseURL string, forceSecure bool) *Handler {
		dialect, dsn := util.GetTestDBConfig("handler_secure_cookies_test")
		cfg := &config.Config{
			DB:                 config.Database{Dialect: dialect, DSN: dsn},
			JWTSecret:          "test-secret-0123456789-0123456789",
			Hashing:            config.Hashing{BcryptCost: 4},
			Addr:               ":8080",
			ApiKey:             "test-api-key",
			BaseURL:            baseURL,
			ForceSecureCookies: forceSecure,
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

	t.Run("http BaseURL without ForceSecureCookies is not Secure", func(t *testing.T) {
		h := newHandler(t, "http://localhost:8080", false)
		if h.Session.Cookie.Secure {
			t.Error("expected Secure=false for an http:// BaseURL with ForceSecureCookies unset")
		}
	})

	t.Run("https BaseURL is Secure regardless of ForceSecureCookies", func(t *testing.T) {
		h := newHandler(t, "https://example.com", false)
		if !h.Session.Cookie.Secure {
			t.Error("expected Secure=true for an https:// BaseURL")
		}
	})

	t.Run("ForceSecureCookies overrides an http BaseURL", func(t *testing.T) {
		h := newHandler(t, "http://localhost:8080", true)
		if !h.Session.Cookie.Secure {
			t.Error("expected Secure=true when ForceSecureCookies is set, even with an http:// BaseURL (e.g. behind a TLS-terminating proxy)")
		}
	})

	// The oauth_state cookie must agree with the session cookie -- it
	// previously re-derived Secure from BaseURL alone, ignoring
	// ForceSecureCookies, so behind a TLS-terminating proxy with BaseURL
	// left at its http:// default this cookie (unlike the session cookie)
	// went out without Secure.
	t.Run("oauth_state cookie respects ForceSecureCookies with an http BaseURL", func(t *testing.T) {
		h := newHandler(t, "http://localhost:8080", true)
		h.svc.RegisterOAuth2Provider("testprovider", service.OAuth2Provider{
			Config: oauth2.Config{ClientID: "id", ClientSecret: "secret", Endpoint: google.Endpoint},
		})
		req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/testprovider/login", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		var found bool
		for _, c := range w.Result().Cookies() {
			if c.Name == "oauth_state" {
				found = true
				if !c.Secure {
					t.Error("expected oauth_state cookie Secure=true when ForceSecureCookies is set")
				}
			}
		}
		if !found {
			t.Fatal("expected an oauth_state cookie to be set")
		}
	})
}

func TestHandler_RateLimiterProxyHeaderTrust(t *testing.T) {
	newHandler := func(t *testing.T, trustProxyHeaders bool) *Handler {
		dialect, dsn := util.GetTestDBConfig("handler_ratelimit_proxy_test")
		cfg := &config.Config{
			DB:        config.Database{Dialect: dialect, DSN: dsn},
			JWTSecret: "test-secret-0123456789-0123456789",
			Hashing:   config.Hashing{BcryptCost: 4},
			Addr:      ":8080",
			ApiKey:    "test-api-key",
			RateLimit: config.RateLimit{
				Enabled:    true,
				Requests:   1,
				Window:     time.Minute,
				ByClientIP: true,
			},
			TrustProxyHeaders: trustProxyHeaders,
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

	// httptest.NewRequest defaults RemoteAddr to the same synthetic value
	// for every request, so these two requests share one real client IP —
	// the point is whether a different spoofed X-Forwarded-For per request
	// buys a fresh rate-limit bucket anyway.
	doTwoRequests := func(h *Handler, forwardedFor1, forwardedFor2 string) (code1, code2 int) {
		req1 := httptest.NewRequest(http.MethodGet, "/ping", nil)
		req1.Header.Set("X-Forwarded-For", forwardedFor1)
		w1 := httptest.NewRecorder()
		h.ServeHTTP(w1, req1)

		req2 := httptest.NewRequest(http.MethodGet, "/ping", nil)
		req2.Header.Set("X-Forwarded-For", forwardedFor2)
		w2 := httptest.NewRecorder()
		h.ServeHTTP(w2, req2)

		return w1.Code, w2.Code
	}

	t.Run("default: spoofed X-Forwarded-For does not bypass the rate limit", func(t *testing.T) {
		h := newHandler(t, false)
		code1, code2 := doTwoRequests(h, "1.1.1.1", "2.2.2.2")
		if code1 != http.StatusOK {
			t.Fatalf("expected first request to succeed, got %d", code1)
		}
		if code2 != http.StatusTooManyRequests {
			t.Fatalf("expected second request (different spoofed X-Forwarded-For, same real client) to be rate-limited, got %d", code2)
		}
	})

	t.Run("TrustProxyHeaders=true: X-Forwarded-For is honored (opt-in, behind a real proxy)", func(t *testing.T) {
		h := newHandler(t, true)
		code1, code2 := doTwoRequests(h, "1.1.1.1", "2.2.2.2")
		if code1 != http.StatusOK || code2 != http.StatusOK {
			t.Fatalf("expected both requests to succeed as distinct clients, got %d and %d", code1, code2)
		}
	})
}

// newSensitiveRateLimitTestHandler builds a Handler with only the sensitive
// route limiter enabled (the general per-route limiter is left disabled),
// isolating which budget a request in these tests is actually exercising.
// See #201: before this ticket, login/password-reset/OTP endpoints shared
// one budget with every other route in the service.
func newSensitiveRateLimitTestHandler(t *testing.T, requests int) *Handler {
	dialect, dsn := util.GetTestDBConfig("handler_sensitive_ratelimit_test")
	cfg := &config.Config{
		DB:        config.Database{Dialect: dialect, DSN: dsn},
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4},
		Addr:      ":8080",
		ApiKey:    "test-api-key",
		RateLimit: config.RateLimit{
			SensitiveEnabled:  true,
			SensitiveRequests: requests,
			SensitiveWindow:   time.Minute,
			ByClientIP:        true,
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

func sensitiveRateLimitTestFormLoginRequest() *http.Request {
	form := url.Values{"email": {"nobody@example.com"}, "password": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func sensitiveRateLimitTestAPILoginRequest() *http.Request {
	body, _ := json.Marshal(map[string]string{"email": "nobody@example.com", "password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/auth/api/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "test-api-key")
	return req
}

// TestHandler_SensitiveRateLimit_SharedAcrossFormAndAPI proves the Form and
// JSON API versions of a sensitive endpoint (here, /login) draw from the
// same limiter instance rather than each getting their own fresh budget --
// otherwise a caller could double an attack's effective rate simply by
// alternating transports.
func TestHandler_SensitiveRateLimit_SharedAcrossFormAndAPI(t *testing.T) {
	h := newSensitiveRateLimitTestHandler(t, 2)

	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, sensitiveRateLimitTestFormLoginRequest())
	if w1.Code == http.StatusTooManyRequests {
		t.Fatalf("expected request 1 of 2 to not be rate-limited, got 429")
	}

	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, sensitiveRateLimitTestAPILoginRequest())
	if w2.Code == http.StatusTooManyRequests {
		t.Fatalf("expected request 2 of 2 (different transport) to not be rate-limited, got 429")
	}

	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, sensitiveRateLimitTestFormLoginRequest())
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the 3rd login attempt to be rate-limited (Form and API login share one budget), got %d", w3.Code)
	}
}

// TestHandler_SensitiveRateLimit_DoesNotThrottleOtherRoutes proves an
// exhausted sensitive-route budget doesn't affect unrelated routes -- before
// #201, every route (including /ping) shared the single limiter sized for
// slowing down credential stuffing.
func TestHandler_SensitiveRateLimit_DoesNotThrottleOtherRoutes(t *testing.T) {
	h := newSensitiveRateLimitTestHandler(t, 1)

	h.ServeHTTP(httptest.NewRecorder(), sensitiveRateLimitTestFormLoginRequest())
	wBlocked := httptest.NewRecorder()
	h.ServeHTTP(wBlocked, sensitiveRateLimitTestFormLoginRequest())
	if wBlocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the sensitive budget to already be exhausted, got %d", wBlocked.Code)
	}

	wPing := httptest.NewRecorder()
	h.ServeHTTP(wPing, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if wPing.Code != http.StatusOK {
		t.Fatalf("expected /ping to be unaffected by the exhausted sensitive-route budget, got %d", wPing.Code)
	}
}
