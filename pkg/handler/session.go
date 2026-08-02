package handler

import (
	"context"
	"errors"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/gopkg/xlog"
)

const (
	sessionTokensKey             = "tokens"
	sessionImpersonatorTokensKey = "impersonator_tokens"
	sessionImpersonatorIDKey     = "impersonator_id"
)

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

// setImpersonationCookies stashes the admin's current session tokens, then swaps the
// session over to the target user's tokens. Used to start a "swap back"-capable
// impersonation session for cookie-based (form) clients.
func (h *Handler) setImpersonationCookies(ctx context.Context, adminID string, tokenResp *service.TokenResponse) {
	if current, ok := h.GetSessionTokens(ctx); ok {
		h.Session.Put(ctx, sessionImpersonatorTokensKey, current)
	}
	h.Session.Put(ctx, sessionImpersonatorIDKey, adminID)
	h.setAuthCookies(ctx, tokenResp)
}

// clearImpersonationCookies restores the stashed admin tokens into the session, ending
// the impersonation session and returning the caller to their own session. Returns false
// if there was no stashed impersonator session to restore.
func (h *Handler) clearImpersonationCookies(ctx context.Context) bool {
	stashed, ok := h.Session.Get(ctx, sessionImpersonatorTokensKey).(map[string]string)
	if !ok {
		return false
	}
	h.Session.Put(ctx, sessionTokensKey, stashed)
	h.Session.Remove(ctx, sessionImpersonatorTokensKey)
	h.Session.Remove(ctx, sessionImpersonatorIDKey)
	return true
}

// IsImpersonating reports whether the current cookie session is an impersonation
// session, and if so, the acting admin's user ID.
func (h *Handler) IsImpersonating(ctx context.Context) (string, bool) {
	id, ok := h.Session.Get(ctx, sessionImpersonatorIDKey).(string)
	return id, ok && id != ""
}

// GetImpersonator returns the acting admin's user for the current cookie-based
// impersonation session. Returns an error if the current session isn't impersonating.
func (h *Handler) GetImpersonator(ctx context.Context) (*models.User, error) {
	id, ok := h.IsImpersonating(ctx)
	if !ok {
		return nil, errors.New("not impersonating")
	}
	return h.svc.Repo.UserGetByID(ctx, id)
}

// GetImpersonatorID returns the acting admin's user ID from a JWT-authenticated
// (Bearer token) request context, as set by AuthMiddleware from the token's "act"
// claim. Returns an error if the request isn't an impersonation session.
//
// This is the Bearer/JWT-mode counterpart to IsImpersonating/GetImpersonator, which
// operate on cookie-based sessions instead — the two are backed by different
// mechanisms and aren't interchangeable.
func GetImpersonatorID(ctx context.Context) (string, error) {
	id, ok := ctx.Value(ezmiddleware.ImpersonatorContextKey).(string)
	if !ok || id == "" {
		return "", errors.New("not an impersonation session")
	}
	return id, nil
}

// GetSessionTokens retrieves the tokens from the session.
// This helper is useful for middleware or other components that need access to the session tokens.
// Returns (nil, false) if session data is not available in the context.
func (h *Handler) GetSessionTokens(ctx context.Context) (tokens map[string]string, ok bool) {
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
	h.Session.Put(ctx, "_flash."+key, value)
}

// GetFlash retrieves and removes a flash message from the session.
// Returns an empty string if no flash message exists for the given key.
func (h *Handler) GetFlash(ctx context.Context, key string) (msg string) {
	return h.Session.PopString(ctx, "_flash."+key)
}

// GetErrorMessage retrieves and clears any error flash message from the session.
// This is a convenience method for GetFlash(ctx, "error").
func (h *Handler) GetErrorMessage(ctx context.Context) (msg string) {
	return h.Session.PopString(ctx, flashKeyError)
}

// GetSuccessMessage retrieves and clears any success flash message from the session.
// This is a convenience method for GetFlash(ctx, "success").
func (h *Handler) GetSuccessMessage(ctx context.Context) (msg string) {
	return h.Session.PopString(ctx, flashKeySuccess)
}
