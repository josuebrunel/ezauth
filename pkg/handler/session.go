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
	sessionMFATokenKey           = "mfa_pending_token"
	sessionMFAEnrollSecretKey    = "mfa_enroll_secret"
	sessionMFAEnrollURLKey       = "mfa_enroll_otpauth_url"
)

// GetMFAEnrollment returns the TOTP secret and otpauth:// URL stashed by
// FormMFAEnroll for the current session, e.g. for rendering a QR code on the
// enrollment page. Returns ok=false if no enrollment is pending.
func (h *Handler) GetMFAEnrollment(ctx context.Context) (secret, otpauthURL string, ok bool) {
	secret, ok1 := h.Session.Get(ctx, sessionMFAEnrollSecretKey).(string)
	otpauthURL, ok2 := h.Session.Get(ctx, sessionMFAEnrollURLKey).(string)
	return secret, otpauthURL, ok1 && ok2 && secret != ""
}

// stashSessionContext copies session-derived values (the tokens map and the
// cookie-mode impersonator ID) into the request context, so downstream
// handlers can read them without the Handler instance. It must only be called
// after the session has been loaded into the context (i.e. from within
// SessionMiddleware, whose LoadAndSave step runs first) — reading the session
// before that panics (see scs).
func (h *Handler) stashSessionContext(ctx context.Context) context.Context {
	if tokens, ok := h.Session.Get(ctx, sessionTokensKey).(map[string]string); ok && len(tokens) > 0 {
		ctx = context.WithValue(ctx, ezmiddleware.SessionTokensContextKey, tokens)
	}
	if id, ok := h.Session.Get(ctx, sessionImpersonatorIDKey).(string); ok && id != "" {
		ctx = context.WithValue(ctx, ezmiddleware.SessionImpersonatorKey, id)
	}
	return ctx
}

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
// storage mechanisms, so use CurrentImpersonatorID/CurrentImpersonator below if
// your handler needs to support both transports without branching on which applies.
func GetImpersonatorID(ctx context.Context) (string, error) {
	id, ok := ctx.Value(ezmiddleware.ImpersonatorContextKey).(string)
	if !ok || id == "" {
		return "", errors.New("not an impersonation session")
	}
	return id, nil
}

// CurrentImpersonatorID returns the acting admin's user ID for the current
// request, regardless of transport, without needing a Handler instance. It
// checks the cookie-session impersonator stashed into the context by
// SessionMiddleware first, then falls back to the Bearer/JWT "act" claim
// (GetImpersonatorID). Returns ok=false if neither applies.
func CurrentImpersonatorID(ctx context.Context) (string, bool) {
	if id, ok := ctx.Value(ezmiddleware.SessionImpersonatorKey).(string); ok && id != "" {
		return id, true
	}
	if id, err := GetImpersonatorID(ctx); err == nil {
		return id, true
	}
	return "", false
}

// CurrentImpersonatorID returns the acting admin's user ID for the current
// request, regardless of transport: it checks the cookie-session stash first
// (IsImpersonating), then falls back to the Bearer/JWT "act" claim
// (GetImpersonatorID). Returns ok=false if neither applies.
//
// The session-manager middleware (SessionMiddleware/LoadAndSaveMiddleware,
// wired in by default — see Handler.New) always runs before route handlers,
// even on Bearer-only routes, so calling this is safe regardless of which
// transport the current request actually used.
func (h *Handler) CurrentImpersonatorID(ctx context.Context) (string, bool) {
	if id, ok := h.IsImpersonating(ctx); ok {
		return id, true
	}
	if id, err := GetImpersonatorID(ctx); err == nil {
		return id, true
	}
	return "", false
}

// CurrentImpersonator returns the acting admin's user for the current
// request, regardless of transport. Returns an error if the request isn't
// an impersonation session under either transport. See CurrentImpersonatorID.
func (h *Handler) CurrentImpersonator(ctx context.Context) (*models.User, error) {
	id, ok := h.CurrentImpersonatorID(ctx)
	if !ok {
		return nil, errors.New("not impersonating")
	}
	return h.svc.Repo.UserGetByID(ctx, id)
}

// GetSessionTokens retrieves the tokens from the session.
// This helper is useful for middleware or other components that need access to the session tokens.
// Returns (nil, false) if session data is not available in the context.
func (h *Handler) GetSessionTokens(ctx context.Context) (tokens map[string]string, ok bool) {
	tokens, ok = h.Session.Get(ctx, sessionTokensKey).(map[string]string)
	return tokens, ok
}

// GetSessionTokens returns the access/refresh token pair stashed into the
// request context by SessionMiddleware, without needing a Handler instance.
// Returns (nil, false) if no session tokens were stashed (e.g. the request
// didn't go through SessionMiddleware or isn't authenticated via cookies).
func GetSessionTokens(ctx context.Context) (map[string]string, bool) {
	tokens, ok := ctx.Value(ezmiddleware.SessionTokensContextKey).(map[string]string)
	return tokens, ok && len(tokens) > 0
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

// GetSessionOrg returns the "current organization" object from the context.
// This requires it to have been previously set via OrgLoaderMiddleware.
func GetSessionOrg(ctx context.Context) (*models.Organization, error) {
	org, ok := ctx.Value(ezmiddleware.OrgObjectContextKey).(*models.Organization)
	if !ok {
		return nil, errors.New("organization not found in context")
	}
	return org, nil
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
