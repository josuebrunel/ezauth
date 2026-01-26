package migrations

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/josuebrunel/gopkg/xlog"
	"github.com/pressly/goose/v3"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

const (
	DialectPostgres = "postgres"
	DialectSqlite   = "sqlite3"
	DialectMysql    = "mysql"
)

//go:embed postgres sqlite mysql
var embedMigrations embed.FS

type migrationFunc func(db *sql.DB, dir string, opts ...goose.OptionsFunc) error

func MigrateUp(dsn, dialect string) error {
	return runMigration(dsn, dialect, goose.Up, "up")
}

func MigrateDown(dsn, dialect string) error {
	return runMigration(dsn, dialect, goose.Down, "down")
}

func runMigration(dsn, dialect string, command migrationFunc, action string) error {
	if dsn == "" {
		return fmt.Errorf("dsn is required")
	}

	var migrationSubDir string
	switch dialect {
	case DialectPostgres:
		migrationSubDir = "postgres"
	case DialectMysql:
		migrationSubDir = "mysql"
	case DialectSqlite, "sqlite":
		dialect = DialectSqlite
		migrationSubDir = "sqlite"
	default:
		return fmt.Errorf("unknown dialect: %s", dialect)
	}

	rootFS, err := fs.Sub(embedMigrations, migrationSubDir)
	if err != nil {
		return fmt.Errorf("failed to create migration subdir: %w", err)
	}

	db, err := getDBConnection(dialect, dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("failed to set dialect: %w", err)
	}

	goose.SetBaseFS(rootFS)

	xlog.Info(fmt.Sprintf("running migrations %s", action), "dialect", dialect, "folder", migrationSubDir)
	if err := command(db, "."); err != nil {
		return fmt.Errorf("failed to run migrations %s: %w", action, err)
	}

	xlog.Info(fmt.Sprintf("migrations %s ran successfully", action))
	return nil
}

func getDBConnection(dialect string, dsn string) (*sql.DB, error) {
	db, err := sql.Open(dialect, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}
