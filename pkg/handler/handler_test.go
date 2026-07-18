package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"

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
		JWTSecret: "test-secret",
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

	// Reset DB (Down then Up) to handle dirty state from previous tests or manual changes
	if err := migrations.MigrateDownWithDBConn(authSvc.Repo.DB(), dialect); err != nil {
		// Just log error, down might fail if tables don't exist
		t.Logf("failed to run migrations down: %v", err)
	}

	if err := migrations.MigrateUpWithDBConn(authSvc.Repo.DB(), dialect); err != nil {
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

	apiKeyToken := util.RandomString(16)
	_, err = h.svc.Repo.TokenCreate(ctx, &models.Token{
		UserID:    user.ID,
		Token:     apiKeyToken,
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
