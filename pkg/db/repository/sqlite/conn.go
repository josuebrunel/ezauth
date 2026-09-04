package sqlite

import (
	"database/sql"
	"strings"

	"github.com/josuebrunel/gopkg/xlog"
	_ "modernc.org/sqlite"
)

// withForeignKeysPragma ensures every connection opened against dsn enforces
// foreign keys (SQLite has them off by default, per-connection, unlike
// postgres/mysql) — required for the ON DELETE CASCADE constraints declared
// throughout the schema (tokens, audit logs, RBAC role/permission
// assignments, etc.) to actually take effect. modernc.org/sqlite applies
// "_pragma" DSN query params to every new pooled connection, so this is
// pool-safe (a one-off PRAGMA Exec would not be, since database/sql may hand
// out a different underlying connection per query).
func withForeignKeysPragma(dsn string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=foreign_keys(1)"
}

func GetDBConnection(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", withForeignKeysPragma(dsn))
	if err != nil {
		xlog.Error("error connecting to the database", "error", err)
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		xlog.Error("error pinging the database", "error", err)
		return nil, err
	}
	return db, nil
}
