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

func MigrateUpWithDBConn(db *sql.DB, dialect string) error {
	return execGooseMigration(db, dialect, goose.Up, "up")
}

func MigrateDownWithDBConn(db *sql.DB, dialect string) error {
	return execGooseMigration(db, dialect, goose.Down, "down")
}

func getMigrationSubDir(dialect string) (string, error) {
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
		return "", fmt.Errorf("unknown dialect: %s", dialect)
	}
	return migrationSubDir, nil
}

func getRootFS(subDir string) (fs.FS, error) {
	rootFS, err := fs.Sub(embedMigrations, subDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration subdir: %w", err)
	}
	return rootFS, nil
}

func runMigration(dsn, dialect string, command migrationFunc, action string) error {
	if dsn == "" {
		return fmt.Errorf("dsn is required")
	}

	db, err := getDBConnection(dialect, dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	return execGooseMigration(db, dialect, command, action)
}

func execGooseMigration(db *sql.DB, dialect string, command migrationFunc, action string) error {
	migrationSubDir, err := getMigrationSubDir(dialect)
	if err != nil {
		xlog.Error("Failed to get migration dir")
		return err
	}

	rootFS, err := getRootFS(migrationSubDir)
	if err != nil {
		return err
	}

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
