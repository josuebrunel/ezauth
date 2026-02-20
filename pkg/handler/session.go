package handler

import (
	"context"
	"errors"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

const sessionTokensKey = "tokens"

// setAuthCookies sets the access and refresh tokens in the session.
func (h *Handler) setAuthCookies(ctx context.Context, tokenResp *service.TokenResponse) {
	defer func() {
		if r := recover(); r != nil {
			xlog.Debug("failed to set auth cookies: session not loaded", "error", r)
		}
	}()
	tokens := map[string]string{
		"access_token":  tokenResp.AccessToken,
		"refresh_token": tokenResp.RefreshToken,
	}
	h.Session.Put(ctx, sessionTokensKey, tokens)
}

// clearAuthCookies clears the authentication session.
func (h *Handler) clearAuthCookies(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			xlog.Debug("failed to clear auth cookies: session not loaded", "error", r)
		}
	}()
	h.Session.Remove(ctx, sessionTokensKey)
	h.Session.Destroy(ctx)
}

// GetSessionTokens retrieves the tokens from the session.
// This helper is useful for middleware or other components that need access to the session tokens.
// Returns (nil, false) if session data is not available in the context.
func (h *Handler) GetSessionTokens(ctx context.Context) (tokens map[string]string, ok bool) {

	defer func() {
		if recover() != nil {
			tokens = nil
			ok = false
		}
	}()

	tokens, ok = h.Session.Get(ctx, sessionTokensKey).(map[string]string)
	return tokens, ok
}

// GetSessionUser returns the user object from the context.
// This requires the user to be previously set in the context via LoadUserMiddleware.
func GetSessionUser(ctx context.Context) (*models.User, error) {
	user, ok := ctx.Value(ezmiddleware.UserObjectContextKey).(*models.User)
	if !ok {
		return nil, errors.New("user not found in context")
	}
	return user, nil
}

// GetSessionUser returns the authenticated user.
// It checks the context first (user object), then the context (userID), then the session cookies.
func (h *Handler) GetSessionUser(ctx context.Context) (*models.User, error) {

	if user, err := GetSessionUser(ctx); err == nil {
		return user, nil
	}

	if userID, err := GetUserID(ctx); err == nil {
		user, err := h.svc.Repo.UserGetByID(ctx, userID)
		if err == nil {
			return user, nil
		}
	}

	tks, ok := h.GetSessionTokens(ctx)
	if !ok {
		return nil, errors.New("not authenticated")
	}

	token, err := h.svc.Repo.TokenGetByToken(ctx, tks["refresh_token"])
	if err != nil {

		xlog.Debug("failed to get refresh token from session", "error", err)
		return nil, errors.New("not authenticated")
	}

	user, err := h.svc.Repo.UserGetByID(ctx, token.UserID)
	if err != nil {
		return nil, errors.New("not authenticated")
	}

	return user, nil
}

// IsAuthenticated checks if the request is authenticated.
func (h *Handler) IsAuthenticated(ctx context.Context) bool {
	_, err := h.GetSessionUser(ctx)
	return err == nil
}

const (
	flashKeyError   = "_flash.error"
	flashKeySuccess = "_flash.success"
)

// SetFlash stores a flash message in the session.
// Flash messages are one-time messages that are cleared after being read.
func (h *Handler) SetFlash(ctx context.Context, key, value string) {
	defer func() {
		_ = recover()
	}()
	h.Session.Put(ctx, "_flash."+key, value)
}

// GetFlash retrieves and removes a flash message from the session.
// Returns an empty string if no flash message exists for the given key.
func (h *Handler) GetFlash(ctx context.Context, key string) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = ""
		}
	}()
	return h.Session.PopString(ctx, "_flash."+key)
}

// GetErrorMessage retrieves and clears any error flash message from the session.
// This is a convenience method for GetFlash(ctx, "error").
func (h *Handler) GetErrorMessage(ctx context.Context) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = ""
		}
	}()
	return h.Session.PopString(ctx, flashKeyError)
}

// GetSuccessMessage retrieves and clears any success flash message from the session.
// This is a convenience method for GetFlash(ctx, "success").
func (h *Handler) GetSuccessMessage(ctx context.Context) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = ""
		}
	}()
	return h.Session.PopString(ctx, flashKeySuccess)
}
