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
	const secret = "super-secret-at-least-32-characters-long"
	os.Setenv("EZAUTH_API_KEY", "test-api-key")
	os.Setenv("EZAUTH_JWT_SECRET", secret)
	defer os.Unsetenv("EZAUTH_JWT_SECRET")
	defer os.Unsetenv("EZAUTH_API_KEY")

	cfg, err := LoadConfig()
	if err != nil {
		t.Errorf("expected no error when EZAUTH_JWT_SECRET is set, got %v", err)
	}

	if cfg.JWTSecret != secret {
		t.Errorf("expected JWTSecret to be %q, got %q", secret, cfg.JWTSecret)
	}
}

func TestLoadConfig_JWTSecretTooShort(t *testing.T) {
	os.Setenv("EZAUTH_API_KEY", "test-api-key")
	os.Setenv("EZAUTH_JWT_SECRET", "too-short")
	defer os.Unsetenv("EZAUTH_JWT_SECRET")
	defer os.Unsetenv("EZAUTH_API_KEY")

	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error when EZAUTH_JWT_SECRET is shorter than the minimum length, got nil")
	}
}

func TestLoadConfig_JWTSecretLengthNotEnforcedForAsymmetricAlgorithms(t *testing.T) {
	os.Setenv("EZAUTH_API_KEY", "test-api-key")
	os.Setenv("EZAUTH_JWT_SECRET", "unused-for-asymmetric-signing")
	os.Setenv("EZAUTH_JWT_ALGORITHM", "RS256")
	defer os.Unsetenv("EZAUTH_JWT_SECRET")
	defer os.Unsetenv("EZAUTH_API_KEY")
	defer os.Unsetenv("EZAUTH_JWT_ALGORITHM")

	if _, err := LoadConfig(); err != nil {
		t.Errorf("expected the JWTSecret length floor to only apply to HS256, got %v", err)
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
