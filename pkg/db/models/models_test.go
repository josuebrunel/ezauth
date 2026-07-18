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

	t.Run("HasAnyRole", func(t *testing.T) {
		user := &User{Roles: "admin, editor"}

		if !user.HasAnyRole("admin") {
			t.Error("expected HasAnyRole(admin) to be true")
		}
		if !user.HasAnyRole("user", "admin") {
			t.Error("expected HasAnyRole(user, admin) to be true")
		}
		if user.HasAnyRole("user", "guest") {
			t.Error("expected HasAnyRole(user, guest) to be false")
		}
		if user.HasAnyRole() {
			t.Error("expected HasAnyRole() with no args to be false")
		}
	})

	t.Run("HasAllRoles", func(t *testing.T) {
		user := &User{Roles: "admin, editor"}

		if !user.HasAllRoles("admin", "editor") {
			t.Error("expected HasAllRoles(admin, editor) to be true")
		}
		if user.HasAllRoles("admin", "user") {
			t.Error("expected HasAllRoles(admin, user) to be false")
		}
	})

	t.Run("GetRoles", func(t *testing.T) {
		user := &User{Roles: "admin, user, editor"}

		roles := user.GetRoles()
		if len(roles) != 3 {
			t.Fatalf("expected 3 roles, got %d", len(roles))
		}
		if roles[0] != "admin" || roles[1] != "user" || roles[2] != "editor" {
			t.Errorf("unexpected roles: %v", roles)
		}

		empty := &User{}
		if r := empty.GetRoles(); r != nil {
			t.Errorf("expected nil for empty roles, got %v", r)
		}
	})

	t.Run("AddRole", func(t *testing.T) {
		user := &User{}

		user.AddRole("admin")
		if user.Roles != "admin" {
			t.Errorf("expected 'admin', got '%s'", user.Roles)
		}

		user.AddRole("editor")
		if user.Roles != "admin,editor" {
			t.Errorf("expected 'admin,editor', got '%s'", user.Roles)
		}

		user.AddRole("admin")
		if user.Roles != "admin,editor" {
			t.Errorf("expected no duplicate, got '%s'", user.Roles)
		}
	})

	t.Run("RemoveRole", func(t *testing.T) {
		user := &User{Roles: "admin,user,editor"}

		user.RemoveRole("user")
		if user.Roles != "admin,editor" {
			t.Errorf("expected 'admin,editor', got '%s'", user.Roles)
		}

		user.RemoveRole("nonexistent")
		if user.Roles != "admin,editor" {
			t.Errorf("expected unchanged roles, got '%s'", user.Roles)
		}

		user.RemoveRole("admin")
		user.RemoveRole("editor")
		if user.Roles != "" {
			t.Errorf("expected empty roles, got '%s'", user.Roles)
		}
	})

	t.Run("FullName", func(t *testing.T) {
		tests := []struct {
			first, last, expected string
		}{
			{"John", "Doe", "John Doe"},
			{"John", "", "John"},
			{"", "Doe", "Doe"},
			{"", "", ""},
		}
		for _, tt := range tests {
			user := &User{FirstName: tt.first, LastName: tt.last}
			if got := user.FullName(); got != tt.expected {
				t.Errorf("FullName(%q,%q) = %q, want %q", tt.first, tt.last, got, tt.expected)
			}
		}
	})

	t.Run("DisplayName", func(t *testing.T) {
		tests := []struct {
			first, last, username, email, expected string
		}{
			{"John", "Doe", "johnd", "john@test.com", "John Doe"},
			{"", "", "johnd", "john@test.com", "johnd"},
			{"", "", "", "john@test.com", "john"},
		}
		for _, tt := range tests {
			user := &User{
				FirstName: tt.first,
				LastName:  tt.last,
				Username:  tt.username,
				Email:     tt.email,
			}
			if got := user.DisplayName(); got != tt.expected {
				t.Errorf("DisplayName() = %q, want %q", got, tt.expected)
			}
		}
	})

	t.Run("IsOAuth", func(t *testing.T) {
		u := &User{Provider: "google"}
		if !u.IsOAuth() {
			t.Error("expected IsOAuth to be true for google provider")
		}
		u = &User{Provider: "local"}
		if u.IsOAuth() {
			t.Error("expected IsOAuth to be false for local provider")
		}
		u = &User{}
		if u.IsOAuth() {
			t.Error("expected IsOAuth to be false for empty provider")
		}
	})

	t.Run("IsLocal", func(t *testing.T) {
		u := &User{Provider: "local"}
		if !u.IsLocal() {
			t.Error("expected IsLocal to be true for local provider")
		}
		u = &User{}
		if !u.IsLocal() {
			t.Error("expected IsLocal to be true for empty provider")
		}
		u = &User{Provider: "github"}
		if u.IsLocal() {
			t.Error("expected IsLocal to be false for github provider")
		}
	})

	t.Run("Sanitize", func(t *testing.T) {
		user := &User{PasswordHash: "somehash"}
		user.Sanitize()
		if user.PasswordHash != "" {
			t.Error("expected PasswordHash to be cleared after Sanitize")
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
