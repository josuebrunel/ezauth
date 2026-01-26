package postgres

import (
	"database/sql"

	"github.com/josuebrunel/gopkg/xlog"
	_ "github.com/lib/pq"
)

func GetDBConnection(dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
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
