package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestJSONUserInfo_StringID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "user-123", "email": "user@test.com"}`))
	}))
	defer server.Close()

	fn := JSONUserInfo(server.URL, "id", "email")
	token := &oauth2.Token{AccessToken: "mock-token"}
	info, err := fn(context.Background(), token)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if info.ID != "user-123" {
		t.Errorf("expected ID 'user-123', got: %s", info.ID)
	}
	if info.Email != "user@test.com" {
		t.Errorf("expected Email 'user@test.com', got: %s", info.Email)
	}
}

func TestJSONUserInfo_NumericID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id_num": 98765, "email_addr": "num@test.com"}`))
	}))
	defer server.Close()

	fn := JSONUserInfo(server.URL, "id_num", "email_addr")
	token := &oauth2.Token{AccessToken: "mock-token"}
	info, err := fn(context.Background(), token)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if info.ID != "98765" {
		t.Errorf("expected ID '98765', got: %s", info.ID)
	}
	if info.Email != "num@test.com" {
		t.Errorf("expected Email 'num@test.com', got: %s", info.Email)
	}
}

func TestJSONUserInfo_MissingID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"email": "no-id@test.com"}`))
	}))
	defer server.Close()

	fn := JSONUserInfo(server.URL, "id", "email")
	token := &oauth2.Token{AccessToken: "mock-token"}
	_, err := fn(context.Background(), token)
	if err == nil {
		t.Fatal("expected error due to missing ID, got nil")
	}
	if !strings.Contains(err.Error(), `id field "id" not found`) {
		t.Errorf("expected missing id field error message, got: %v", err)
	}
}

func TestDiscordPreset(t *testing.T) {
	p := Discord("discord-client", "discord-secret", "http://localhost/discord")
	if p.Config.ClientID != "discord-client" || p.Config.ClientSecret != "discord-secret" {
		t.Error("incorrect client config for Discord preset")
	}
	if len(p.Config.Scopes) != 2 || p.Config.Scopes[0] != "identify" || p.Config.Scopes[1] != "email" {
		t.Errorf("incorrect scopes for Discord preset: %v", p.Config.Scopes)
	}
}

func TestGitLabPreset(t *testing.T) {
	p := GitLab("gitlab-client", "gitlab-secret", "http://localhost/gitlab")
	if p.Config.ClientID != "gitlab-client" || p.Config.ClientSecret != "gitlab-secret" {
		t.Error("incorrect client config for GitLab preset")
	}
	if len(p.Config.Scopes) != 1 || p.Config.Scopes[0] != "read_user" {
		t.Errorf("incorrect scopes for GitLab preset: %v", p.Config.Scopes)
	}
}

func TestSlackPreset(t *testing.T) {
	p := Slack("slack-client", "slack-secret", "http://localhost/slack")
	if p.Config.ClientID != "slack-client" || p.Config.ClientSecret != "slack-secret" {
		t.Error("incorrect client config for Slack preset")
	}
	if len(p.Config.Scopes) != 2 || p.Config.Scopes[0] != "openid" || p.Config.Scopes[1] != "email" {
		t.Errorf("incorrect scopes for Slack preset: %v", p.Config.Scopes)
	}
}

func TestLinkedInPreset(t *testing.T) {
	p := LinkedIn("li-client", "li-secret", "http://localhost/linkedin")
	if p.Config.ClientID != "li-client" || p.Config.ClientSecret != "li-secret" {
		t.Error("incorrect client config for LinkedIn preset")
	}
	if len(p.Config.Scopes) != 3 || p.Config.Scopes[0] != "openid" || p.Config.Scopes[1] != "profile" || p.Config.Scopes[2] != "email" {
		t.Errorf("incorrect scopes for LinkedIn preset: %v", p.Config.Scopes)
	}
}

func TestSpotifyPreset(t *testing.T) {
	p := Spotify("spotify-client", "spotify-secret", "http://localhost/spotify")
	if p.Config.ClientID != "spotify-client" || p.Config.ClientSecret != "spotify-secret" {
		t.Error("incorrect client config for Spotify preset")
	}
	if len(p.Config.Scopes) != 2 || p.Config.Scopes[0] != "user-read-email" || p.Config.Scopes[1] != "user-read-private" {
		t.Errorf("incorrect scopes for Spotify preset: %v", p.Config.Scopes)
	}
}

func TestOIDCDiscovery_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			doc := oidcDiscovery{
				AuthorizationEndpoint: "https://idp.com/auth",
				TokenEndpoint:         "https://idp.com/token",
				UserinfoEndpoint:      "https://idp.com/userinfo",
			}
			json.NewEncoder(w).Encode(doc)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	p, err := OIDC(context.Background(), server.URL, "oidc-client", "oidc-secret", "http://localhost/callback", []string{"openid", "email"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if p.Config.ClientID != "oidc-client" || p.Config.ClientSecret != "oidc-secret" || p.Config.RedirectURL != "http://localhost/callback" {
		t.Error("incorrect core config for OIDC provider")
	}
	if p.Config.Endpoint.AuthURL != "https://idp.com/auth" || p.Config.Endpoint.TokenURL != "https://idp.com/token" {
		t.Errorf("incorrect URLs extracted in OIDC config: auth=%s, token=%s", p.Config.Endpoint.AuthURL, p.Config.Endpoint.TokenURL)
	}
	if len(p.Config.Scopes) != 2 || p.Config.Scopes[0] != "openid" || p.Config.Scopes[1] != "email" {
		t.Errorf("incorrect scopes for OIDC provider: %v", p.Config.Scopes)
	}
}

func TestOIDCDiscovery_MissingFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// missing userinfo_endpoint
			w.Write([]byte(`{"authorization_endpoint": "https://auth", "token_endpoint": "https://token"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := OIDC(context.Background(), server.URL, "client", "secret", "http://callback", []string{"openid"})
	if err == nil {
		t.Fatal("expected error due to missing userinfo_endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "missing userinfo_endpoint") {
		t.Errorf("expected missing userinfo endpoint error message, got: %v", err)
	}
}
