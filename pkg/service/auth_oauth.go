package service

import (
	"context"
	"fmt"
	"time"
)

// GetAuthURL returns the authorization URL for the specified provider
func (a *Auth) GetAuthURL(providerName string, state string) (string, error) {
	provider := a.getProvider(providerName)
	if provider == nil {
		return "", fmt.Errorf("provider %s not found", providerName)
	}
	return provider.GetAuthorizationURL(state), nil
}

// SignInWithOAuth handles the OAuth callback: exchanges code, gets user info, and signs in/up
func (a *Auth) SignInWithOAuth(ctx context.Context, providerName, code string) (*Session, error) {
	provider := a.getProvider(providerName)
	if provider == nil {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}

	// 1. Exchange code for token
	oauthToken, err := provider.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	// 2. Get User Info
	userInfo, err := provider.GetUserInfo(ctx, oauthToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// 3. Check if Account exists
	account, err := a.Config.Storage.GetAccount(ctx, provider.Name(), userInfo.ID)
	if err != nil {
		return nil, err
	}

	var userID string

	if account != nil {
		// Account exists -> User exists
		userID = account.UserID
		// Update tokens if needed? (Not implemented for brevity, but good practice)
	} else {
		// New Account
		// Check if user exists by email
		existingUser, err := a.Config.Storage.GetUserByEmail(ctx, userInfo.Email)
		if err != nil {
			return nil, err
		}

		if existingUser != nil {
			// Link to existing user
			userID = existingUser.ID
		} else {
			// Create new user
			newUser := &User{
				ID:            GenerateID(),
				Email:         userInfo.Email,
				Name:          userInfo.Name,
				Image:         userInfo.Image,
				EmailVerified: true, // OAuth usually implies verified email
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}
			createdUser, err := a.Config.Storage.CreateUser(ctx, newUser)
			if err != nil {
				return nil, err
			}
			userID = createdUser.ID
		}

		// Create Account
		newAccount := &Account{
			ID:                GenerateID(),
			UserID:            userID,
			Provider:          provider.Name(),
			ProviderAccountID: userInfo.ID,
			AccessToken:       oauthToken.AccessToken,
			RefreshToken:      oauthToken.RefreshToken,
			// ExpiresAt: ...
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		_, err = a.Config.Storage.CreateAccount(ctx, newAccount)
		if err != nil {
			return nil, err
		}
	}

	// 4. Create Session
	session := &Session{
		ID:        GenerateID(),
		UserID:    userID,
		Token:     GenerateToken(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}

	return a.Config.Storage.CreateSession(ctx, session)
}

func (a *Auth) getProvider(name string) OAuthProvider {
	for _, p := range a.Config.Providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}
