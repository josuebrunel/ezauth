package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type OAuth2UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (a *Auth) OAuth2GetConfig(provider string) (*oauth2.Config, error) {
	switch provider {
	case "google":
		return &oauth2.Config{
			ClientID:     a.Cfg.OAuth2.Google.ClientID,
			ClientSecret: a.Cfg.OAuth2.Google.ClientSecret,
			RedirectURL:  a.Cfg.OAuth2.Google.RedirectURL,
			Scopes:       strings.Split(a.Cfg.OAuth2.Google.Scopes, ","),
			Endpoint:     google.Endpoint,
		}, nil
	case "github":
		return &oauth2.Config{
			ClientID:     a.Cfg.OAuth2.Github.ClientID,
			ClientSecret: a.Cfg.OAuth2.Github.ClientSecret,
			RedirectURL:  a.Cfg.OAuth2.Github.RedirectURL,
			Scopes:       strings.Split(a.Cfg.OAuth2.Github.Scopes, ","),
			Endpoint:     github.Endpoint,
		}, nil
	case "facebook":
		return &oauth2.Config{
			ClientID:     a.Cfg.OAuth2.Facebook.ClientID,
			ClientSecret: a.Cfg.OAuth2.Facebook.ClientSecret,
			RedirectURL:  a.Cfg.OAuth2.Facebook.RedirectURL,
			Scopes:       strings.Split(a.Cfg.OAuth2.Facebook.Scopes, ","),
			Endpoint:     facebook.Endpoint,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (a *Auth) OAuth2GetUserInfo(ctx context.Context, provider string, token *oauth2.Token) (*OAuth2UserInfo, error) {
	var userInfoURL string
	switch provider {
	case "google":
		userInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
	case "github":
		userInfoURL = "https://api.github.com/user"
	case "facebook":
		userInfoURL = "https://graph.facebook.com/me?fields=id,email"
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	resp, err := client.Get(userInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	userInfo := &OAuth2UserInfo{}

	// Normalize ID and Email based on provider
	switch provider {
	case "google":
		if sub, ok := data["sub"].(string); ok {
			userInfo.ID = sub
		}
		if email, ok := data["email"].(string); ok {
			userInfo.Email = email
		}
	case "github":
		if id, ok := data["id"].(float64); ok {
			userInfo.ID = fmt.Sprintf("%.0f", id)
		}
		if email, ok := data["email"].(string); ok {
			userInfo.Email = email
		}
	case "facebook":
		if id, ok := data["id"].(string); ok {
			userInfo.ID = id
		}
		if email, ok := data["email"].(string); ok {
			userInfo.Email = email
		}
	}

	if userInfo.ID == "" {
		return nil, errors.New("could not retrieve user id from provider")
	}

	return userInfo, nil
}

func (a *Auth) OAuth2Authenticate(ctx context.Context, provider string, userInfo *OAuth2UserInfo) (*models.User, error) {
	// 1. Try to find user by provider and provider ID
	user, err := a.Repo.UserGetByProvider(ctx, provider, userInfo.ID)
	if err == nil && user != nil {
		// User found, update email if it changed
		if userInfo.Email != "" && user.Email != userInfo.Email {
			user.Email = userInfo.Email
			return a.Repo.UserUpdate(ctx, user)
		}
		return user, nil
	}

	// 2. If not found, try to find user by email
	if userInfo.Email != "" {
		user, err = a.Repo.UserGetByEmail(ctx, userInfo.Email)
		if err == nil && user != nil {
			// Found by email, link provider
			user.Provider = provider
			user.ProviderID = &userInfo.ID
			return a.Repo.UserUpdate(ctx, user)
		}
	}

	// 3. Create new user
	user = &models.User{
		Email:         userInfo.Email,
		Provider:      provider,
		ProviderID:    &userInfo.ID,
		EmailVerified: true,
	}

	return a.Repo.UserCreate(ctx, user)
}
