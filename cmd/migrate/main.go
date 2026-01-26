package main

import (
	"flag"
	"os"

	"github.com/josuebrunel/ezauth/pkg/db/migrations"
	"github.com/josuebrunel/gopkg/xlog"
)

func main() {
	dialect := flag.String("dialect", "sqlite", "database dialect (postgres, mysql, sqlite3)")
	dsn := flag.String("dsn", "", "database connection string")
	up := flag.Bool("up", false, "run migrations up")
	down := flag.Bool("down", false, "run migrations down")
	flag.Parse()

	if *dsn == "" {
		xlog.Error("dsn is required")
		os.Exit(1)
	}

	if *up {
		if err := migrations.MigrateUp(*dsn, *dialect); err != nil {
			xlog.Error("failed to run migrations up", "error", err)
			os.Exit(1)
		}
		return
	}

	if *down {
		if err := migrations.MigrateDown(*dsn, *dialect); err != nil {
			xlog.Error("failed to run migrations down", "error", err)
			os.Exit(1)
		}
	}
}
