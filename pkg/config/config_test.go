package config

import (
	"os"
	"testing"
)

func TestLoadConfig_RequiredJWTSecret(t *testing.T) {
	// Ensure EZAUTH_JWT_SECRET is unset
	os.Unsetenv("EZAUTH_JWT_SECRET")

	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error when EZAUTH_JWT_SECRET is missing, got nil")
	}
}

func TestLoadConfig_Success(t *testing.T) {
	os.Setenv("EZAUTH_API_KEY", "test-api-key")
	os.Setenv("EZAUTH_JWT_SECRET", "super-secret")
	defer os.Unsetenv("EZAUTH_JWT_SECRET")
	defer os.Unsetenv("EZAUTH_API_KEY")

	cfg, err := LoadConfig()
	if err != nil {
		t.Errorf("expected no error when EZAUTH_JWT_SECRET is set, got %v", err)
	}

	if cfg.JWTSecret != "super-secret" {
		t.Errorf("expected JWTSecret to be 'super-secret', got '%s'", cfg.JWTSecret)
	}
}

func TestConfig_Sanitized(t *testing.T) {
	cfg := Config{
		JWTSecret: "real-jwt-secret",
		ApiKey:    "real-api-key",
	}
	cfg.SMTP.Password = "real-smtp-password"
	cfg.OAuth2.Google.ClientSecret = "real-google-secret"
	cfg.OAuth2.Github.ClientSecret = "real-github-secret"

	sanitized := cfg.Sanitized()

	if sanitized.JWTSecret != "***" {
		t.Errorf("expected JWTSecret to be redacted, got '%s'", sanitized.JWTSecret)
	}
	if sanitized.ApiKey != "***" {
		t.Errorf("expected ApiKey to be redacted, got '%s'", sanitized.ApiKey)
	}
	if sanitized.SMTP.Password != "***" {
		t.Errorf("expected SMTP.Password to be redacted, got '%s'", sanitized.SMTP.Password)
	}
	if sanitized.OAuth2.Google.ClientSecret != "***" {
		t.Errorf("expected Google ClientSecret to be redacted, got '%s'", sanitized.OAuth2.Google.ClientSecret)
	}
	if sanitized.OAuth2.Github.ClientSecret != "***" {
		t.Errorf("expected Github ClientSecret to be redacted, got '%s'", sanitized.OAuth2.Github.ClientSecret)
	}

	// Ensure original values are preserved
	if cfg.JWTSecret != "real-jwt-secret" {
		t.Errorf("original JWTSecret was modified, got '%s'", cfg.JWTSecret)
	}
}
