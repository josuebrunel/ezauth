package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/josuebrunel/ezauth/pkg/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestCustomOAuth2ProviderRegistry(t *testing.T) {
	cfg := &config.Config{
		OAuth2: config.OAuth2{
			Google: config.OAuth2Google{
				ClientID:     "g-id",
				ClientSecret: "g-secret",
				RedirectURL:  "http://localhost/google/callback",
				Scopes:       "email,profile",
			},
		},
	}
	auth, err := New(&config.Config{JWTSecret: "test-secret"}, nil, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	auth.Cfg = cfg

	// Register Google as a built-in provider (simulating registerBuiltinProviders)
	auth.RegisterOAuth2Provider("google", OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     cfg.OAuth2.Google.ClientID,
			ClientSecret: cfg.OAuth2.Google.ClientSecret,
			RedirectURL:  cfg.OAuth2.Google.RedirectURL,
			Scopes:       strings.Split(cfg.OAuth2.Google.Scopes, ","),
			Endpoint:     google.Endpoint,
		},
		UserInfoFn: func(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error) {
			return &OAuth2UserInfo{ID: "test-id", Email: "test@example.com"}, nil
		},
	})

	// Test 1: Unsupported provider before registration
	_, err = auth.OAuth2GetConfig("okta")
	if err == nil {
		t.Error("expected error for unregistered provider, got nil")
	}

	_, err = auth.OAuth2GetUserInfo(context.Background(), "okta", &oauth2.Token{AccessToken: "token"})
	if err == nil {
		t.Error("expected error for unregistered provider, got nil")
	}

	// Test 2: Google works (registered as built-in)
	gConf, err := auth.OAuth2GetConfig("google")
	if err != nil {
		t.Fatalf("unexpected error getting google config: %v", err)
	}
	if gConf.ClientID != "g-id" {
		t.Errorf("expected client ID 'g-id', got: %s", gConf.ClientID)
	}

	// Register a custom provider
	customP := OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     "okta-client",
			ClientSecret: "okta-secret",
			RedirectURL:  "http://localhost/okta/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://okta.com/auth",
				TokenURL: "https://okta.com/token",
			},
		},
		UserInfoFn: func(ctx context.Context, token *oauth2.Token) (*OAuth2UserInfo, error) {
			if token.AccessToken != "secret-token" {
				return nil, errors.New("invalid token")
			}
			return &OAuth2UserInfo{
				ID:    "okta-123",
				Email: "okta@test.com",
			}, nil
		},
	}

	auth.RegisterOAuth2Provider("okta", customP)

	// Test 3: Custom provider Config is successfully retrieved
	oktaConf, err := auth.OAuth2GetConfig("okta")
	if err != nil {
		t.Fatalf("failed to get okta config: %v", err)
	}
	if oktaConf.ClientID != "okta-client" || oktaConf.ClientSecret != "okta-secret" || oktaConf.RedirectURL != "http://localhost/okta/callback" {
		t.Error("retrieved custom provider config is incorrect")
	}
	if oktaConf.Endpoint.AuthURL != "https://okta.com/auth" || oktaConf.Endpoint.TokenURL != "https://okta.com/token" {
		t.Error("retrieved custom provider config endpoints are incorrect")
	}

	// Test 4: Custom provider UserInfoFn is successfully executed
	info, err := auth.OAuth2GetUserInfo(context.Background(), "okta", &oauth2.Token{AccessToken: "secret-token"})
	if err != nil {
		t.Fatalf("failed to get okta user info: %v", err)
	}
	if info.ID != "okta-123" || info.Email != "okta@test.com" {
		t.Errorf("incorrect custom user info retrieved: id=%s, email=%s", info.ID, info.Email)
	}

	// Invalid token fails
	_, err = auth.OAuth2GetUserInfo(context.Background(), "okta", &oauth2.Token{AccessToken: "wrong-token"})
	if err == nil {
		t.Error("expected error for invalid token, got nil")
	}

	// Test 5: Google is still unaffected after okta registration
	gConf2, err := auth.OAuth2GetConfig("google")
	if err != nil {
		t.Fatalf("unexpected error getting google config: %v", err)
	}
	if gConf2.ClientID != "g-id" {
		t.Errorf("expected client ID 'g-id', got: %s", gConf2.ClientID)
	}
}
