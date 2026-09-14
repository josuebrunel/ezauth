package config

import (
	"encoding/json"
	"os"
	"strings"
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
	if !cfg.RateLimit.Enabled {
		t.Error("expected RateLimit.Enabled to default to true (secure by default)")
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

func TestLoadConfig_FailsFastOnFullyDisabledAccountLockout(t *testing.T) {
	const secret = "super-secret-at-least-32-characters-long"
	os.Setenv("EZAUTH_API_KEY", "test-api-key")
	os.Setenv("EZAUTH_JWT_SECRET", secret)
	os.Setenv("EZAUTH_ACCOUNT_LOCKOUT_ENABLED", "false")
	os.Setenv("EZAUTH_ACCOUNT_LOCKOUT_MAX_ATTEMPTS", "0")
	os.Setenv("EZAUTH_ACCOUNT_LOCKOUT_DURATION", "0s")
	defer os.Unsetenv("EZAUTH_API_KEY")
	defer os.Unsetenv("EZAUTH_JWT_SECRET")
	defer os.Unsetenv("EZAUTH_ACCOUNT_LOCKOUT_ENABLED")
	defer os.Unsetenv("EZAUTH_ACCOUNT_LOCKOUT_MAX_ATTEMPTS")
	defer os.Unsetenv("EZAUTH_ACCOUNT_LOCKOUT_DURATION")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected an error when AccountLockout resolves to its fully zero value, got nil")
	}
	if !strings.Contains(err.Error(), "ACCOUNT_LOCKOUT") {
		t.Errorf("expected the error to name AccountLockout, got: %v", err)
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

// TestConfig_JSONMarshalNeverLeaksSecrets proves secrets never reach a
// json.Marshal of the raw Config -- unlike Sanitized(), which only helps a
// caller who remembers to call it, json:"-" on every secret field makes
// Sanitized() belt-and-braces instead of the only line of defense (e.g.
// against a debug endpoint or an errant log call that marshals Config
// directly).
func TestConfig_JSONMarshalNeverLeaksSecrets(t *testing.T) {
	cfg := Config{
		JWTSecret:  "super-secret-jwt-value",
		CSRFSecret: "super-secret-csrf-value",
		ApiKey:     "super-secret-api-key-value",
	}
	cfg.SMTP.Password = "super-secret-smtp-password"
	cfg.SMS.AuthToken = "super-secret-sms-auth-token"
	cfg.OAuth2.Google.ClientSecret = "super-secret-google-client-secret"
	cfg.OAuth2.Github.ClientSecret = "super-secret-github-client-secret"
	cfg.OAuth2.Facebook.ClientSecret = "super-secret-facebook-client-secret"
	cfg.OAuth2.Discord.ClientSecret = "super-secret-discord-client-secret"
	cfg.OAuth2.GitLab.ClientSecret = "super-secret-gitlab-client-secret"
	cfg.OAuth2.Slack.ClientSecret = "super-secret-slack-client-secret"
	cfg.OAuth2.LinkedIn.ClientSecret = "super-secret-linkedin-client-secret"
	cfg.OAuth2.Spotify.ClientSecret = "super-secret-spotify-client-secret"
	cfg.JWT.PrivateKey = "super-secret-jwt-private-key"

	secrets := []string{
		cfg.JWTSecret, cfg.CSRFSecret, cfg.ApiKey, cfg.SMTP.Password, cfg.SMS.AuthToken,
		cfg.OAuth2.Google.ClientSecret, cfg.OAuth2.Github.ClientSecret,
		cfg.OAuth2.Facebook.ClientSecret, cfg.OAuth2.Discord.ClientSecret,
		cfg.OAuth2.GitLab.ClientSecret, cfg.OAuth2.Slack.ClientSecret,
		cfg.OAuth2.LinkedIn.ClientSecret, cfg.OAuth2.Spotify.ClientSecret,
		cfg.JWT.PrivateKey,
	}

	// Deliberately marshal the RAW config, not cfg.Sanitized() -- this is
	// exactly the "forgot to sanitize" scenario json:"-" protects against.
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	for _, secret := range secrets {
		if strings.Contains(string(out), secret) {
			t.Errorf("secret value %q leaked into JSON output: %s", secret, out)
		}
	}
}
