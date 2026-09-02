package handler

import (
	"context"
	"testing"

	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/ezauth/pkg/service"
)

func TestHandler_CurrentImpersonatorID(t *testing.T) {
	h := setupTestHandler(t)
	admin, _, _ := registerAndLogin(t, h, "unified-impersonate-admin")

	sessionCtx, err := h.Session.Load(context.Background(), "")
	if err != nil {
		t.Fatalf("failed to load session: %v", err)
	}

	t.Run("neither transport is impersonating", func(t *testing.T) {
		if id, ok := h.CurrentImpersonatorID(sessionCtx); ok {
			t.Errorf("expected ok=false, got (%s, true)", id)
		}
		if _, err := h.CurrentImpersonator(sessionCtx); err == nil {
			t.Error("expected CurrentImpersonator to error when nothing is impersonating")
		}
	})

	t.Run("Bearer/JWT transport", func(t *testing.T) {
		ctx := context.WithValue(sessionCtx, ezmiddleware.ImpersonatorContextKey, admin.ID)

		id, ok := h.CurrentImpersonatorID(ctx)
		if !ok || id != admin.ID {
			t.Fatalf("expected (%s, true), got (%s, %v)", admin.ID, id, ok)
		}

		got, err := h.CurrentImpersonator(ctx)
		if err != nil {
			t.Fatalf("CurrentImpersonator failed: %v", err)
		}
		if got.ID != admin.ID {
			t.Errorf("expected admin %s, got %s", admin.ID, got.ID)
		}
	})

	t.Run("cookie-session transport", func(t *testing.T) {
		tokenResp := &service.TokenResponse{AccessToken: "access", RefreshToken: "refresh"}
		h.setImpersonationCookies(sessionCtx, admin.ID, tokenResp)

		id, ok := h.CurrentImpersonatorID(sessionCtx)
		if !ok || id != admin.ID {
			t.Fatalf("expected (%s, true), got (%s, %v)", admin.ID, id, ok)
		}

		got, err := h.CurrentImpersonator(sessionCtx)
		if err != nil {
			t.Fatalf("CurrentImpersonator failed: %v", err)
		}
		if got.ID != admin.ID {
			t.Errorf("expected admin %s, got %s", admin.ID, got.ID)
		}
	})
}
