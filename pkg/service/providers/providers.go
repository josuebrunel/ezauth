// Package providers provides predefined OAuth2 and OIDC configurations for popular identity providers.
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/josuebrunel/ezauth/pkg/service"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// JSONUserInfo builds a UserInfoFn that makes a GET request to the specified url,
// decodes the response as a flat JSON object, and extracts the idField and emailField.
func JSONUserInfo(url string, idField, emailField string) func(ctx context.Context, token *oauth2.Token) (*service.OAuth2UserInfo, error) {
	return func(ctx context.Context, token *oauth2.Token) (*service.OAuth2UserInfo, error) {
		client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
		resp, err := client.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to make userinfo request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("userinfo request returned status %s", resp.Status)
		}

		var data map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
		}

		idVal, ok := data[idField]
		if !ok || idVal == nil {
			return nil, fmt.Errorf("id field %q not found in userinfo response", idField)
		}

		idStr := fmt.Sprintf("%v", idVal)
		if idStr == "" {
			return nil, fmt.Errorf("id field %q is empty in userinfo response", idField)
		}

		var emailStr string
		if emailVal, ok := data[emailField]; ok && emailVal != nil {
			emailStr = fmt.Sprintf("%v", emailVal)
		}

		var emailVerified bool
		if ev, ok := data["email_verified"]; ok && ev != nil {
			switch v := ev.(type) {
			case bool:
				emailVerified = v
			case string:
				emailVerified = v == "true" || v == "1"
			case float64:
				emailVerified = v != 0
			}
		}

		return &service.OAuth2UserInfo{
			ID:            idStr,
			Email:         emailStr,
			EmailVerified: emailVerified,
		}, nil
	}
}

// Discord returns a preconfigured service.OAuth2Provider for Discord.
func Discord(clientID, clientSecret, redirectURL string) service.OAuth2Provider {
	return service.OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint:     endpoints.Discord,
		},
		UserInfoFn: JSONUserInfo("https://discord.com/api/users/@me", "id", "email"),
	}
}

// GitLab returns a preconfigured service.OAuth2Provider for GitLab.
func GitLab(clientID, clientSecret, redirectURL string) service.OAuth2Provider {
	return service.OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"read_user"},
			Endpoint:     endpoints.GitLab,
		},
		UserInfoFn: JSONUserInfo("https://gitlab.com/api/v4/user", "id", "email"),
	}
}

// Slack returns a preconfigured service.OAuth2Provider for Slack.
func Slack(clientID, clientSecret, redirectURL string) service.OAuth2Provider {
	return service.OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email"},
			Endpoint:     endpoints.Slack,
		},
		UserInfoFn: JSONUserInfo("https://slack.com/api/openid.connect.userInfo", "sub", "email"),
	}
}

// LinkedIn returns a preconfigured service.OAuth2Provider for LinkedIn.
func LinkedIn(clientID, clientSecret, redirectURL string) service.OAuth2Provider {
	return service.OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     endpoints.LinkedIn,
		},
		UserInfoFn: JSONUserInfo("https://api.linkedin.com/v2/userinfo", "sub", "email"),
	}
}

// Spotify returns a preconfigured service.OAuth2Provider for Spotify.
func Spotify(clientID, clientSecret, redirectURL string) service.OAuth2Provider {
	return service.OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"user-read-email", "user-read-private"},
			Endpoint:     endpoints.Spotify,
		},
		UserInfoFn: JSONUserInfo("https://api.spotify.com/v1/me", "id", "email"),
	}
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// OIDC fetches openid-configuration from issuerURL, extracts necessary endpoints, and builds a service.OAuth2Provider.
func OIDC(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL string, scopes []string) (service.OAuth2Provider, error) {
	issuerURL = strings.TrimSuffix(issuerURL, "/")
	discoveryURL := issuerURL + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return service.OAuth2Provider{}, fmt.Errorf("failed to create OIDC discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return service.OAuth2Provider{}, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return service.OAuth2Provider{}, fmt.Errorf("OIDC discovery returned status %s", resp.Status)
	}

	var doc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return service.OAuth2Provider{}, fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	if doc.AuthorizationEndpoint == "" {
		return service.OAuth2Provider{}, fmt.Errorf("missing authorization_endpoint in OIDC discovery document")
	}
	if doc.TokenEndpoint == "" {
		return service.OAuth2Provider{}, fmt.Errorf("missing token_endpoint in OIDC discovery document")
	}
	if doc.UserinfoEndpoint == "" {
		return service.OAuth2Provider{}, fmt.Errorf("missing userinfo_endpoint in OIDC discovery document")
	}

	return service.OAuth2Provider{
		Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  doc.AuthorizationEndpoint,
				TokenURL: doc.TokenEndpoint,
			},
		},
		UserInfoFn: JSONUserInfo(doc.UserinfoEndpoint, "sub", "email"),
	}, nil
}
