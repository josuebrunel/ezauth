package handler

import (
	"context"
	"errors"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

const sessionTokensKey = "tokens"

// setAuthCookies sets the access and refresh tokens in the session.
func (h *Handler) setAuthCookies(ctx context.Context, tokenResp *service.TokenResponse) {
	tokens := map[string]string{
		"access_token":  tokenResp.AccessToken,
		"refresh_token": tokenResp.RefreshToken,
	}
	h.Session.Put(ctx, sessionTokensKey, tokens)
}

// clearAuthCookies clears the authentication session.
func (h *Handler) clearAuthCookies(ctx context.Context) {
	h.Session.Remove(ctx, sessionTokensKey)
	h.Session.Destroy(ctx)
}

// GetSessionTokens retrieves the tokens from the session.
// This helper is useful for middleware or other components that need access to the session tokens.
func (h *Handler) GetSessionTokens(ctx context.Context) (map[string]string, bool) {
	tokens, ok := h.Session.Get(ctx, sessionTokensKey).(map[string]string)
	return tokens, ok
}

// GetSessionUser returns the user object from the context.
// This requires the user to be previously set in the context via LoadUserMiddleware.
func GetSessionUser(ctx context.Context) (*models.User, error) {
	user, ok := ctx.Value(userObjectContextKey).(*models.User)
	if !ok {
		return nil, errors.New("user not found in context")
	}
	return user, nil
}

// GetSessionUser returns the authenticated user.
// It checks the context first (user object), then the context (userID), then the session cookies.
func (h *Handler) GetSessionUser(ctx context.Context) (*models.User, error) {
	// 1. Check if user object is already in context (fastest)
	if user, err := GetSessionUser(ctx); err == nil {
		return user, nil
	}

	// 2. Check if UserID is in context (e.g. from AuthMiddleware)
	if userID, err := GetUserID(ctx); err == nil {
		user, err := h.svc.Repo.UserGetByID(ctx, userID)
		if err == nil {
			return user, nil
		}
	}

	// 3. Check Session Tokens (Cookies)
	tks, ok := h.GetSessionTokens(ctx)
	if !ok {
		return nil, errors.New("not authenticated")
	}

	token, err := h.svc.Repo.TokenGetByToken(ctx, tks["refresh_token"])
	if err != nil {
		// Only log if it's an unexpected error, consistent with original logic
		xlog.Debug("failed to get refresh token from session", "error", err)
		return nil, errors.New("not authenticated")
	}

	user, err := h.svc.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		return nil, errors.New("not authenticated")
	}

	return user, nil
}
