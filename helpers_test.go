package ezauth

import (
	"context"
	"testing"

	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
)

func TestGetSessionTokens_Standalone(t *testing.T) {
	if tokens, err := GetSessionTokens(context.Background()); err == nil {
		t.Errorf("expected error without session middleware, got tokens: %v", tokens)
	}

	ctx := context.WithValue(context.Background(), ezmiddleware.SessionTokensContextKey, map[string]string{
		"access_token":  "at",
		"refresh_token": "rt",
	})
	tokens, err := GetSessionTokens(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens["access_token"] != "at" || tokens["refresh_token"] != "rt" {
		t.Errorf("unexpected tokens: %v", tokens)
	}
}

func TestCurrentImpersonatorID_Standalone(t *testing.T) {
	if id, ok := CurrentImpersonatorID(context.Background()); ok || id != "" {
		t.Errorf("expected no impersonator on empty context, got %q ok=%v", id, ok)
	}

	ctx := context.WithValue(context.Background(), ezmiddleware.ImpersonatorContextKey, "admin")
	id, ok := CurrentImpersonatorID(ctx)
	if !ok || id != "admin" {
		t.Errorf("expected JWT impersonator admin, got %q ok=%v", id, ok)
	}
}
