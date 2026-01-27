NAME=ezauthapi
SRC=cmd/ezauthapi/main.go
BIN=./bin/${NAME}

# Default database target
DB ?= sqlite
MIGRATION_DIR=pkg/db/migrations

# Database configurations
ifeq ($(DB),postgres)
	DRIVER := postgres
	DSN := postgres://postgres:postgrespwd@127.0.0.1:5436/ezauthdb?sslmode=disable
	DIR := $(MIGRATION_DIR)/postgres
	BOBBIN := psql
else ifeq ($(DB),mysql)
	DRIVER := mysql
	DSN := "ezauth:ezauthpwd@tcp(127.0.0.1:3366)/ezauthdb"
	DIR := $(MIGRATION_DIR)/mysql
	BOBBIN := mysql
else
	DRIVER := sqlite
	DSN := "ezauth.db"
	DIR := $(MIGRATION_DIR)/sqlite
	BOBBIN := sqlite
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

test:
	go test -failfast ./... -v -p=1 -count=1 -coverprofile .coverage.txt
	go tool cover -func .coverage.txt

build:
	go build -o ${BIN} ${SRC}


run: build
	${BIN}
