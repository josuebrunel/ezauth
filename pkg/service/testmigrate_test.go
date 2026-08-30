package service

import (
	"database/sql"
	"sync"

	"github.com/josuebrunel/ezauth/pkg/db/migrations"
)

var (
	ensureMigratedMu    sync.Mutex
	ensureMigratedState = map[string]error{}
)

// ensureMigrated resets (Down) and (re-)applies (Up) migrations for a given dialect+dsn at
// most once per test binary process; subsequent calls with an identical dialect+dsn reuse the
// cached result instead of re-running Down+Up against the same database. This matters in CI,
// where every setup*TestDB helper in this package is invoked against one fixed, shared DSN
// (configured via env vars for the whole job), so without memoizing this, every one of the
// setup calls in this package redundantly resets the same real postgres/mysql database.
// Locally, sqlite tests get a unique per-call DSN (see util.GetTestDBConfig), so each call is a
// genuinely new, unmigrated database and this cache never hits — behavior there is unchanged.
func ensureMigrated(db *sql.DB, dialect, dsn string) error {
	key := dialect + "|" + dsn

	ensureMigratedMu.Lock()
	defer ensureMigratedMu.Unlock()

	if err, ok := ensureMigratedState[key]; ok {
		return err
	}

	_ = migrations.MigrateDownWithDBConn(db, dialect) // best-effort: no-op on a fresh DB
	err := migrations.MigrateUpWithDBConn(db, dialect)
	ensureMigratedState[key] = err
	return err
}
