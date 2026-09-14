package migrations

import (
	"fmt"
	"testing"
	"time"
)

// TestMigrateUp_AcceptsSqlite3Alias proves the "sqlite3" dialect alias
// (config.Database.Dialect's own documented default, and a common sqlite
// driver-name alias) actually works end to end through the DSN-based
// MigrateUp/MigrateDown entry points -- getDBConnection previously passed
// "sqlite3" straight to sql.Open, but the registered driver name is
// "sqlite", so this failed with "unknown driver" despite every other
// dialect switch in this package accepting "sqlite3" as a valid alias.
func TestMigrateUp_AcceptsSqlite3Alias(t *testing.T) {
	dsn := fmt.Sprintf("file:migrate_sqlite3_alias_%d?mode=memory&cache=shared", time.Now().UnixNano())

	if err := MigrateUp(dsn, "sqlite3", ""); err != nil {
		t.Fatalf("MigrateUp with dialect %q: %v", "sqlite3", err)
	}
	if err := MigrateDown(dsn, "sqlite3", ""); err != nil {
		t.Fatalf("MigrateDown with dialect %q: %v", "sqlite3", err)
	}
}

func TestGetDBConnection_RejectsNothingButNormalizesSqlite3(t *testing.T) {
	dsn := fmt.Sprintf("file:migrate_getconn_%d?mode=memory&cache=shared", time.Now().UnixNano())

	db, err := getDBConnection("sqlite3", dsn)
	if err != nil {
		t.Fatalf("getDBConnection(%q, ...) unexpected error: %v", "sqlite3", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("connection opened via the sqlite3 alias failed to ping: %v", err)
	}
}
