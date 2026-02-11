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
	DSN := root:mysqlpwd@tcp(127.0.0.1:3306)/ezauthdb?parseTime=true
	DIR := $(MIGRATION_DIR)/mysql
	BOBBIN := mysql
else
	DRIVER := sqlite
	DSN := "ezauth.db"
	DIR := $(MIGRATION_DIR)/sqlite
	BOBBIN := sqlite
endif

# Commands
.PHONY: migration-status migration-up migration-down migration-reset migration-create swagger

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

tidy:
	go mod tidy
	go mod vendor

build: tidy
	go build -o ${BIN} ${SRC}

run: build
	${BIN}

swagger:
	swag init -g pkg/handler/handler.go --parseDependency -o pkg/handler/docs

doc.build:
	mkdocs build

doc.serve:
	mkdocs serve

doc.gh-pages:
	mkdocs gh-deploy

# Docker database containers for testing
.PHONY: db-up db-down db-logs

db-up:
	@echo "Starting database containers..."
	@docker compose up -d
	@echo "Waiting for databases to be ready..."
	@sleep 5

db-down:
	@echo "Stopping database containers..."
	@docker compose down

db-logs:
	@docker compose logs -f

# Run tests on specific database
.PHONY: test-sqlite test-postgres test-mysql test-all-dbs

test-sqlite:
	@echo "=== Testing SQLite ==="
	EZAUTH_DB_DIALECT=sqlite EZAUTH_DB_DSN="file:test.db?mode=memory&cache=shared" \
		go test -failfast ./... -v -p=1 -count=1

test-postgres: db-up
	@echo "=== Testing PostgreSQL ==="
	EZAUTH_DB_DIALECT=postgres EZAUTH_DB_DSN="postgres://postgres:postgrespwd@127.0.0.1:5436/ezauthdb?sslmode=disable" \
		go test -failfast ./... -v -p=1 -count=1

test-mysql: db-up
	@echo "=== Testing MySQL ==="
	EZAUTH_DB_DIALECT=mysql EZAUTH_DB_DSN="root:mysqlpwd@tcp(127.0.0.1:3306)/ezauthdb?parseTime=true&multiStatements=true" \
		go test -failfast ./... -v -p=1 -count=1

test-all-dbs: db-up test-sqlite test-postgres test-mysql
	@echo "=== All database tests completed ==="