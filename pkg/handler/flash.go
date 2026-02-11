package handler

import (
	"context"
)

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
