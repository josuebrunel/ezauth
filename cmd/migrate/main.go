package main

import (
	"database/sql"
	"embed"
	"flag"
	"io/fs"
	"os"

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

//go:embed migrations
var embedMigrations embed.FS

func main() {
	dialect := flag.String("dialect", "sqlite3", "database dialect (postgres, mysql, sqlite3)")
	dsn := flag.String("dsn", "", "database connection string")
	flag.Parse()

	if *dsn == "" {
		xlog.Error("dsn is required")
		os.Exit(1)
	}

	var migrationSubDir string
	switch *dialect {
	case DialectPostgres:
		migrationSubDir = "migrations/postgres"
	case DialectMysql:
		migrationSubDir = "migrations/mysql"
	case DialectSqlite, "sqlite":
		*dialect = DialectSqlite
		migrationSubDir = "migrations/sqlite"
	default:
		xlog.Error("unknown dialect", "dialect", *dialect)
		os.Exit(1)
	}

	rootFS, err := fs.Sub(embedMigrations, migrationSubDir)
	if err != nil {
		xlog.Error("failed to create migration subdir", "error", err, "path", migrationSubDir)
		os.Exit(1)
	}

	db := getDBConnection(*dialect, *dsn)
	defer db.Close()

	if err := goose.SetDialect(*dialect); err != nil {
		xlog.Error("failed to set dialect", "error", err, "dialect", *dialect)
		os.Exit(1)
	}

	goose.SetBaseFS(rootFS)

	xlog.Info("running migrations", "dialect", *dialect, "folder", migrationSubDir)
	if err := goose.Up(db, "."); err != nil {
		xlog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	xlog.Info("migrations ran successfully")
}

func getDBConnection(dialect string, dsn string) *sql.DB {
	db, err := sql.Open(dialect, dsn)
	if err != nil {
		xlog.Error("failed to connect to database", "error", err, "dialect", dialect)
		os.Exit(1)
	}

	if err := db.Ping(); err != nil {
		xlog.Error("failed to ping database", "error", err)
		os.Exit(1)
	}

	return db
}
