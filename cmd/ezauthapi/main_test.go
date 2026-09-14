package main

import (
	"strings"
	"testing"
)

func TestConfirmDestructiveMigration(t *testing.T) {
	t.Run("down without -yes is refused", func(t *testing.T) {
		if err := confirmDestructiveMigration("down", false, "postgres", "postgres://user:pass@host/db"); err == nil {
			t.Fatal("expected an error for down without -yes, got nil")
		}
	})

	t.Run("down with -yes is allowed", func(t *testing.T) {
		if err := confirmDestructiveMigration("down", true, "postgres", "postgres://user:pass@host/db"); err != nil {
			t.Fatalf("expected down with -yes to be allowed, got %v", err)
		}
	})

	t.Run("up is never gated", func(t *testing.T) {
		if err := confirmDestructiveMigration("up", false, "postgres", "postgres://user:pass@host/db"); err != nil {
			t.Fatalf("expected up to never require -yes, got %v", err)
		}
	})

	t.Run("revert is never gated", func(t *testing.T) {
		if err := confirmDestructiveMigration("revert", false, "postgres", "postgres://user:pass@host/db"); err != nil {
			t.Fatalf("expected revert to never require -yes, got %v", err)
		}
	})

	t.Run("the refusal message redacts DSN credentials", func(t *testing.T) {
		err := confirmDestructiveMigration("down", false, "postgres", "postgres://user:s3cr3t@host/db")
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if got := err.Error(); strings.Contains(got, "s3cr3t") {
			t.Errorf("expected the DSN password to be redacted from the error message, got: %s", got)
		}
	})
}
