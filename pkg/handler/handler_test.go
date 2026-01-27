package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/service"
	_ "github.com/mattn/go-sqlite3"
)

func setupTestHandler(t *testing.T) *Handler {
	// Use in-memory SQLite database
	dsn := fmt.Sprintf("file:%d?mode=memory&cache=shared", time.Now().UnixNano())
	cfg := &config.Config{
		DB: config.Database{
			Dialect: "sqlite3",
			DSN:     dsn,
		},
		JWTSecret: "test-secret",
		Addr:      ":8080",
	}
	authSvc, err := service.NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}

	// Run migrations
	if err := migrations.MigrateUpWithDBConn(authSvc.Repo.DB(), "sqlite3"); err != nil {
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

	email := "test@example.com"
	password := "password123"
	var accessToken string
	var refreshToken string

	// 1. Register
	t.Run("Register", func(t *testing.T) {
		reqBody := map[string]any{
			"email":    email,
			"password": password,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
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
	})

	// 2. Login
	t.Run("Login", func(t *testing.T) {
		reqBody := map[string]any{
			"email":    email,
			"password": password,
		}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
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
		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
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
		req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
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
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	// 6. Delete User
	t.Run("DeleteUser", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/auth/user", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestHandler_PasswordReset(t *testing.T) {
	h := setupTestHandler(t)
	email := "reset@example.com"
	password := "old-password"

	// 1. Register user
	reqBody := map[string]any{"email": email, "password": password}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)

	// 2. Request reset
	reqBody = map[string]any{"email": email}
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/password-reset/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 3. Get token from mock mailer
	mockMailer := h.svc.Mailer.(*service.MockMailer)
	sentBody := mockMailer.SentEmails[0]["body"]
	tokenValue := sentBody[len(sentBody)-64:]

	// 4. Confirm reset
	newPassword := "new-password"
	reqBody = map[string]any{"token": tokenValue, "password": newPassword}
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/password-reset/confirm", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Login with new password
	reqBody = map[string]any{"email": email, "password": newPassword}
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after password reset, got %d", w.Code)
	}
}

func TestHandler_Passwordless(t *testing.T) {
	h := setupTestHandler(t)
	email := "magic@example.com"

	// 1. Request magic link
	reqBody := map[string]any{"email": email}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/auth/passwordless/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. Get token from mock mailer
	mockMailer := h.svc.Mailer.(*service.MockMailer)
	sentBody := mockMailer.SentEmails[0]["body"]
	tokenValue := sentBody[len(sentBody)-64:]

	// 3. Login with magic link
	req = httptest.NewRequest(http.MethodGet, "/auth/passwordless/login?token="+tokenValue, nil)
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

func TestHandler_Unauthorized(t *testing.T) {
	h := setupTestHandler(t)

	t.Run("UserInfo_NoToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})

	t.Run("UserInfo_InvalidToken", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", w.Code)
		}
	})
}
