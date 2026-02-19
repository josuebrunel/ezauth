package models

import (
	"testing"
)

func TestUserHelpers(t *testing.T) {
	t.Run("HasRole", func(t *testing.T) {
		user := &User{Roles: "admin, user, editor"}

		if !user.HasRole("admin") {
			t.Error("expected user to have admin role")
		}
		if !user.HasRole("user") {
			t.Error("expected user to have user role")
		}
		if !user.HasRole("editor") {
			t.Error("expected user to have editor role")
		}
		if user.HasRole("guest") {
			t.Error("expected user to not have guest role")
		}

		userNoRoles := &User{}
		if userNoRoles.HasRole("admin") {
			t.Error("expected user with no roles to not have admin role")
		}
	})

	t.Run("AppMeta Helpers", func(t *testing.T) {
		user := &User{}

		// Test SetAppMeta
		user.SetAppMeta("theme", "dark")
		user.SetAppMeta("notifications", true)
		user.SetAppMeta("count", 42.0) // JSON numbers are often float64

		// Test GetAppMeta
		theme, ok := GetAppMeta[string](user, "theme")
		if !ok || theme != "dark" {
			t.Errorf("expected theme dark, got %v (ok: %v)", theme, ok)
		}

		notifs, ok := GetAppMeta[bool](user, "notifications")
		if !ok || !notifs {
			t.Errorf("expected notifications true, got %v (ok: %v)", notifs, ok)
		}

		// Test non-existent key
		_, ok = GetAppMeta[string](user, "missing")
		if ok {
			t.Error("expected false for missing key")
		}

		// Test wrong type
		_, ok = GetAppMeta[int](user, "theme")
		if ok {
			t.Error("expected false for wrong type assumption")
		}
	})

	t.Run("UserMeta Helpers", func(t *testing.T) {
		user := &User{}

		// Test SetMeta
		user.SetMeta("nickname", "jdoe")

		// Test GetMeta
		nick, ok := GetMeta[string](user, "nickname")
		if !ok || nick != "jdoe" {
			t.Errorf("expected nickname jdoe, got %v (ok: %v)", nick, ok)
		}
	})

	t.Run("JSON Marshaling", func(t *testing.T) {
		// Verify that SetMeta properly affects the JSONMap which handles marshaling
		user := &User{}
		user.SetMeta("key", "val")

		// Manually check the map
		if user.UserMetadata["key"] != "val" {
			t.Error("expected SetMeta to update UserMetadata map")
		}

		// Test Valid JSONMap Value/Scan (indirectly via model usage, but good to check basic map behavior)
		jm := JSONMap{"foo": "bar"}
		val, err := jm.Value()
		if err != nil {
			t.Fatalf("JSONMap Value() error: %v", err)
		}

		jsonStr, ok := val.([]byte)
		if !ok {
			t.Fatal("expected []byte from JSONMap Value()")
		}

		var jm2 JSONMap
		err = jm2.Scan(jsonStr)
		if err != nil {
			t.Fatalf("JSONMap Scan() error: %v", err)
		}

		if jm2["foo"] != "bar" {
			t.Error("expected JSONMap to roundtrip correctly")
		}
	})
}
