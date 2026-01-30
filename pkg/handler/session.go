package handler

import (
	"context"

	"github.com/josuebrunel/ezauth/pkg/service"
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
