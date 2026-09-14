package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
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

// RandomString returns a random hex string of length n (n/2 random bytes).
// Unlike an earlier version, a crypto/rand failure is returned as an error
// rather than silently producing "" -- a caller comparing that against an
// expected value with a constant-time compare would otherwise treat two
// empty strings as a match, turning an RNG failure into a fail-open check
// (see OAuth2Login's state cookie, this function's one production caller).
func RandomString(n int) (string, error) {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random string: %w", err)
	}
	return hex.EncodeToString(b), nil
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

// LikeEscapeChar is the escape character used by EscapeLikePattern. Callers
// building a LIKE query from the escaped output must pair it with an
// explicit `ESCAPE '!'` clause, since dialects disagree on (or don't define)
// a default LIKE escape character.
const LikeEscapeChar = "!"

// EscapeLikePattern escapes the LIKE wildcard characters (%, _) and the
// escape character itself in s, so the result can be wrapped in wildcards
// (e.g. "%"+EscapeLikePattern(s)+"%") and matched literally rather than as a
// user-controlled pattern. Must be paired with an `ESCAPE '!'` clause.
func EscapeLikePattern(s string) string {
	r := strings.NewReplacer(
		LikeEscapeChar, LikeEscapeChar+LikeEscapeChar,
		"%", LikeEscapeChar+"%",
		"_", LikeEscapeChar+"_",
	)
	return r.Replace(s)
}

var (
	dsnUserInfoRE  = regexp.MustCompile(`([^:@/\s]+):([^@/\s]+)@`)
	dsnPasswordKVR = regexp.MustCompile(`(?i)(password|pwd)=\S+`)
)

// RedactDSN masks credentials embedded in a database connection string so it
// is safe to include in logs. It handles URL-style DSNs
// (postgres://user:pass@host/db), the MySQL driver's user:pass@tcp(host)/db
// form, and libpq key=value DSNs (password=... / pwd=...). Strings with no
// recognizable credentials (e.g. a SQLite file path) are returned unchanged.
func RedactDSN(dsn string) string {
	dsn = dsnUserInfoRE.ReplaceAllString(dsn, "$1:***@")
	dsn = dsnPasswordKVR.ReplaceAllString(dsn, "$1=***")
	return dsn
}

// HashToken returns the SHA-256 hex digest of a bearer-style token value
// (refresh token, password-reset/passwordless/invitation/email-change/
// trusted-device/MFA-pre-auth token, API key, ...), for storage and lookup.
// These are high-entropy random values (see RandomString and similar
// generators), so SHA-256 with no salt is sufficient -- unlike a password,
// there's no meaningful dictionary/rainbow-table attack surface once the
// input space is that large. Storing the hash instead of the raw value
// means a DB-read compromise (backup leak, replica misconfiguration, ...)
// doesn't hand over directly usable credentials. Callers must still return
// the original raw value to whoever needs to present it back (a link, an
// Authorization header, ...) -- only the stored/looked-up copy is hashed.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
