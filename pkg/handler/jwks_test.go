package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func setupRS256TestHandler(t *testing.T) *Handler {
	dialect, dsn := util.GetTestDBConfig("handler_jwks_test")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal RSA private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "unused-for-asymmetric",
		JWT:       config.JWT{Algorithm: "RS256", PrivateKey: privPEM, PublicKey: pubPEM},
		Hashing:   config.Hashing{BcryptCost: 4},
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

func TestHandler_RS256_LoginAndJWKS(t *testing.T) {
	h := setupRS256TestHandler(t)

	email := util.UniqueEmail("jwks")
	password := "password123"
	var accessToken string

	t.Run("Register issues an RS256-signed token", func(t *testing.T) {
		reqBody := map[string]any{"email": email, "password": password}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/auth/api/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", w.Code, w.Body.String())
		}
		var resp testResponse[service.TokenResponse]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Data.AccessToken == "" {
			t.Fatal("expected an access token")
		}
		accessToken = resp.Data.AccessToken
	})

	t.Run("the RS256 token authenticates a protected route", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/api/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("X-API-Key", "test-api-key")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("JWKS publishes the RS256 public key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp testResponse[service.JWKSet]
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Data.Keys) != 1 {
			t.Fatalf("expected 1 published key, got %d", len(resp.Data.Keys))
		}
		if resp.Data.Keys[0].Kty != "RSA" || resp.Data.Keys[0].Alg != "RS256" {
			t.Errorf("expected an RSA/RS256 JWK, got %+v", resp.Data.Keys[0])
		}
		if resp.Data.Keys[0].N == "" || resp.Data.Keys[0].E == "" {
			t.Error("expected non-empty RSA modulus/exponent")
		}
	})
}

func TestHandler_JWKS_EmptyForDefaultHS256(t *testing.T) {
	h := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp testResponse[service.JWKSet]
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Data.Keys) != 0 {
		t.Errorf("expected no published keys for the default HS256 mode, got %d", len(resp.Data.Keys))
	}
}
