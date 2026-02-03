package mysql

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/josuebrunel/gopkg/xlog"
)

func GetDBConnection(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
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
