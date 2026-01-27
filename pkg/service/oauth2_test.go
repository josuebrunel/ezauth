package service

import (
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
)

func TestOAuth2GetConfig(t *testing.T) {
	cfg := &config.Config{
		OAuth2: config.OAuth2{
			Google: config.OAuth2Google{
				ClientID:     "g-id",
				ClientSecret: "g-secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       "email,profile",
			},
		},
	}
	auth := &Auth{Cfg: cfg}

	t.Run("Google", func(t *testing.T) {
		conf, err := auth.OAuth2GetConfig("google")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.ClientID != "g-id" {
			t.Errorf("expected client id 'g-id', got '%s'", conf.ClientID)
		}
		if len(conf.Scopes) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(conf.Scopes))
		}
	})

	t.Run("Unsupported", func(t *testing.T) {
		_, err := auth.OAuth2GetConfig("unknown")
		if err == nil {
			t.Fatal("expected error for unknown provider")
		}
	})
}
