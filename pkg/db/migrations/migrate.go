package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/josuebrunel/gopkg/xlog"
	"github.com/pressly/goose/v3"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

const (
	DialectPostgres = "postgres"
	DialectSqlite   = "sqlite"
	DialectMysql    = "mysql"
)

//go:embed postgres sqlite mysql
var embedMigrations embed.FS

func MigrateUp(dsn, dialect, schema string) error {
	return runMigration(dsn, dialect, schema, "up")
}

func MigrateDown(dsn, dialect, schema string) error {
	return runMigration(dsn, dialect, schema, "down")
}

func MigrateUpWithDBConn(db *sql.DB, dialect string) error {
	// For existing DB connection, we assume schema setup is already done or not needed
	return execGooseMigration(db, dialect, "up")
}

func MigrateDownWithDBConn(db *sql.DB, dialect string) error {
	return execGooseMigration(db, dialect, "down")
}

func getMigrationSubDir(dialect string) (string, error) {
	var migrationSubDir string
	switch dialect {
	case DialectPostgres:
		migrationSubDir = "postgres"
	case DialectSqlite, "sqlite3":
		migrationSubDir = "sqlite"
	case DialectMysql:
		migrationSubDir = "mysql"
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

func runMigration(dsn, dialect, schema string, action string) error {
	if dsn == "" {
		return fmt.Errorf("dsn is required")
	}

	db, err := getDBConnection(dialect, dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if dialect == DialectPostgres && schema != "" {
		// Set the search path to the specified schema
		if _, err := db.Exec("CREATE SCHEMA IF NOT EXISTS " + schema); err != nil {
			xlog.Error("failed to create schema", "error", err, "schema", schema)
			return err
		}
		if _, err := db.Exec("SET search_path TO " + schema); err != nil {
			xlog.Error("failed to set search_path", "error", err, "schema", schema)
			return err
		}
	}

	return execGooseMigration(db, dialect, action)
}

func execGooseMigration(db *sql.DB, dialect string, action string) error {
	migrationSubDir, err := getMigrationSubDir(dialect)
	if err != nil {
		xlog.Error("Failed to get migration dir")
		return err
	}

	rootFS, err := getRootFS(migrationSubDir)
	if err != nil {
		return err
	}

	var d goose.Dialect

	switch dialect {
	case DialectPostgres:
		d = goose.DialectPostgres
	case DialectMysql:
		d = goose.DialectMySQL
	case DialectSqlite, "sqlite3":
		d = goose.DialectSQLite3
	default:
		return fmt.Errorf("unknown dialect: %s", dialect)
	}

	provider, err := goose.NewProvider(d, db, rootFS, goose.WithTableName("ezauth_goose_db_version"))
	if err != nil {
		return fmt.Errorf("failed to create goose provider: %w", err)
	}

	xlog.Info(fmt.Sprintf("running migrations %s", action), "dialect", dialect, "folder", migrationSubDir)

	var results []*goose.MigrationResult
	if action == "up" {
		results, err = provider.Up(context.Background())
	} else if action == "down" {
		var res *goose.MigrationResult
		res, err = provider.Down(context.Background())
		if res != nil {
			results = append(results, res)
		}
	} else {
		return fmt.Errorf("unknown action: %s", action)
	}

	if err != nil {
		return fmt.Errorf("failed to run migrations %s: %w", action, err)
	}

	xlog.Info(fmt.Sprintf("migrations %s ran successfully", action), "count", len(results))
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
