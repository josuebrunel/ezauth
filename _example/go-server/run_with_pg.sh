# Launch the PG db in a container and run this command
set -x

EZAUTH_DB_DIALECT=postgres EZAUTH_DB_DSN="postgres://user:password@127.0.0.1:3001/ezauth?sslmode=disable" go run main.go
