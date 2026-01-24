package config

import (
	"os"
	"testing"

	"github.com/josuebrunel/gopkg/xenv"
	"github.com/josuebrunel/gopkg/xlog"
)

func TestConfig(t *testing.T) {
	t.Run("Defaults", func(t *testing.T) {
		// Note: This assumes the environment does not have EZAUTH_ prefixed variables set.
		// If you run this in an environment with EZAUTH_ADDR set, this test might fail.
		var cfg Config
		if err := xenv.LoadWithOptions(&cfg, xenv.Options{Prefix: "EZAUTH"}); err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		if cfg.Addr != ":8080" {
			t.Errorf("expected default Addr ':8080', got '%s'", cfg.Addr)
		}
		if cfg.Debug != false {
			t.Errorf("expected default Debug 'false', got '%v'", cfg.Debug)
		}
		if cfg.DB.Dialect != "sqlite" {
			t.Errorf("expected default DB.Dialect 'sqlite', got '%s'", cfg.DB.Dialect)
		}
		if cfg.OAuth2.Google.Name != "google" {
			t.Errorf("expected default OAuth2.Google.Name 'google', got '%s'", cfg.OAuth2.Google.Name)
		}
	})

	t.Run("Overrides", func(t *testing.T) {
		envVars := map[string]string{
			"EZAUTH_ADDR":                        ":3000",
			"EZAUTH_DEBUG":                       "true",
			"EZAUTH_DB_DIALECT":                  "postgres",
			"EZAUTH_DB_DSN":                      "postgres://localhost:5432/db",
			"EZAUTH_SECRET":                      "mysecret",
			"EZAUTH_JWT_SECRET":                  "myjwtsecret",
			"EZAUTH_OAUTH2_GOOGLE_CLIENT_ID":     "g_id",
			"EZAUTH_OAUTH2_GITHUB_CLIENT_SECRET": "gh_secret",
		}

		for k, v := range envVars {
			os.Setenv(k, v)
		}

		xlog.Info("addr", "addr", os.Getenv("EZAUTH_ADDR"))

		var cfg Config
		if err := xenv.LoadWithOptions(&cfg, xenv.Options{Prefix: "EZAUTH_"}); err != nil {
			t.Fatalf("failed to load config: %v", err)
		}

		if cfg.Addr != ":3000" {
			t.Errorf("expected Addr ':3000', got '%s'", cfg.Addr)
		}
		if !cfg.Debug {
			t.Errorf("expected Debug 'true', got '%v'", cfg.Debug)
		}
		if cfg.DB.Dialect != "postgres" {
			t.Errorf("expected DB.Dialect 'postgres', got '%s'", cfg.DB.Dialect)
		}
		if cfg.DB.DSN != "postgres://localhost:5432/db" {
			t.Errorf("expected DB.DSN 'postgres://localhost:5432/db', got '%s'", cfg.DB.DSN)
		}
		if cfg.Secret != "mysecret" {
			t.Errorf("expected Secret 'mysecret', got '%s'", cfg.Secret)
		}
		if cfg.JWTSecret != "myjwtsecret" {
			t.Errorf("expected JWTSecret 'myjwtsecret', got '%s'", cfg.JWTSecret)
		}
		if cfg.OAuth2.Google.ClientID != "g_id" {
			t.Errorf("expected OAuth2.Google.ClientID 'g_id', got '%s'", cfg.OAuth2.Google.ClientID)
		}
		if cfg.OAuth2.Github.ClientSecret != "gh_secret" {
			t.Errorf("expected OAuth2.Github.ClientSecret 'gh_secret', got '%s'", cfg.OAuth2.Github.ClientSecret)
		}
	})
}
