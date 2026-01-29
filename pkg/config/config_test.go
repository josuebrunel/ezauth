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
