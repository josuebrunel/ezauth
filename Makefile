# Default database target
DB ?= sqlite3

# Database configurations
ifeq ($(DB),postgres)
	DRIVER := postgres
	DSN := postgres://postgres:postgrespwd@127.0.0.1:5436/ezauthdb?sslmode=disable
	DIR := migrations/postgres
else ifeq ($(DB),mysql)
	DRIVER := mysql
	DSN := "ezauth:ezauthpwd@tcp(127.0.0.1:3366)/ezauthdb"
	DIR := migrations/mysql
else
	DRIVER := sqlite3
	DSN := "ezauth.db"
	DIR := migrations/sqlite
endif

# Commands
.PHONY: migration-status migration-up migration-down migration-reset migration-create

migration-status:
	goose -dir $(DIR) $(DRIVER) $(DSN) status

migration-up:
	goose -dir $(DIR) $(DRIVER) $(DSN) up

migration-down:
	goose -dir $(DIR) $(DRIVER) $(DSN) down

migration-reset:
	goose -dir $(DIR) $(DRIVER) $(DSN) reset

migration-create:
	@read -p "Enter migration name: " name; \
		goose -dir $(DIR) $(DRIVER) $(DSN) create $$name sql



migrate:
	go build -o bin/migrate cmd/migrate/main.go
	./bin/migrate --dialect $(DB) --dsn $(DSN)
