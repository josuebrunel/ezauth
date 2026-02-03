package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/gofrs/uuid/v5" // Added import
)

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func Deref[T any](t *T) T {
	if t == nil {
		var zero T
		return zero
	}
	return *t
}

func RandomString(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// NewID generates a new V4 UUID
func NewID() string {
	id, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return id.String()
}

// NewIDStripped generates a new V4 UUID without hyphens
func NewIDStripped() string {
	id, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(id.Bytes())
}

// GetTestDBConfig returns the dialect and DSN for tests based on environment variables.
// Falls back to SQLite in-memory if not set.
// For persistent databases (postgres, mysql), returns the same DSN from env.
// For SQLite, generates a unique in-memory DSN per test to avoid conflicts.
func GetTestDBConfig(testName string) (dialect, dsn string) {
	dialect = os.Getenv("EZAUTH_DB_DIALECT")
	dsn = os.Getenv("EZAUTH_DB_DSN")

	// Default to SQLite in-memory for local development
	if dialect == "" {
		dialect = "sqlite"
	}

	// Generate unique DSN for SQLite test isolation
	if dsn == "" {
		dsn = fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", testName, time.Now().UnixNano())
	}

	return dialect, dsn
}

// IsPersistentDB returns true if the database is persistent (not in-memory SQLite).
// Persistent databases may require cleanup between tests.
func IsPersistentDB() bool {
	dialect := os.Getenv("EZAUTH_DB_DIALECT")
	return dialect == "postgres" || dialect == "mysql"
}

// UniqueEmail generates a unique email address for tests to avoid conflicts in persistent DBs.
func UniqueEmail(prefix string) string {
	return fmt.Sprintf("%s_%d@test.com", prefix, time.Now().UnixNano())
}
