package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/josuebrunel/ezauth"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	cmd := "serve"
	rest := []string{}
	if len(os.Args) > 1 {
		cmd = os.Args[1]
		rest = os.Args[2:]
	}

	switch cmd {
	case "serve":
		serve(&cfg)
	case "migrate":
		migrate(&cfg, rest)
	case "create-admin":
		createAdmin(&cfg, rest)
	default:
		log.Fatalf("unknown command %q (expected serve, migrate, or create-admin)", cmd)
	}
}

// serve runs migrations then starts the HTTP server -- the default action,
// preserved exactly as before subcommands existed so existing deployments
// (Docker CMD, systemd units, ...) that invoke ezauthapi with no arguments
// keep working unchanged.
func serve(cfg *config.Config) {
	xlog.Info("starting ezauth", "addr", cfg.Addr, "db_dialect", cfg.DB.Dialect, "config", cfg.Sanitized())
	auth, err := ezauth.New(cfg, "auth")
	if err != nil {
		log.Fatalf("failed to initialize ezauth: %v", err)
	}

	if err := auth.Migrate(); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	xlog.Info("starting server")
	auth.Handler.Run()
}

// confirmDestructiveMigration refuses the down action (which resets the
// schema to version 0 -- every ezauth table is dropped, with no way to
// recover the data short of a backup) unless yes is set. Without this, a
// bare `ezauthapi migrate down` (one easy typo away from `up`, or a
// copy-pasted command against the wrong DSN) would run immediately.
func confirmDestructiveMigration(action string, yes bool, dialect, dsn string) error {
	if action != "down" || yes {
		return nil
	}
	return fmt.Errorf("refusing to run migrate down without -yes: this drops every ezauth table on %s (dialect=%s). Re-run with -yes to confirm.", util.RedactDSN(dsn), dialect)
}

// migrate runs a one-shot migration action against the configured database,
// then exits -- for deploy pipelines that want migrations as a separate step
// from starting the server.
func migrate(cfg *config.Config, args []string) {
	if len(args) == 0 {
		log.Fatalf("usage: ezauthapi migrate <up|down|revert> [-dialect=...] [-dsn=...] [-schema=...]")
	}
	action := args[0]

	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dialect := fs.String("dialect", "", "database dialect, overrides EZAUTH_DB_DIALECT")
	dsn := fs.String("dsn", "", "database DSN, overrides EZAUTH_DB_DSN")
	schema := fs.String("schema", "", "database schema (postgres only), overrides EZAUTH_DB_SCHEMA")
	yes := fs.Bool("yes", false, "required for the down action: confirms you intend to drop every ezauth table")
	fs.Parse(args[1:])

	if *dialect != "" {
		cfg.DB.Dialect = *dialect
	}
	if *dsn != "" {
		cfg.DB.DSN = *dsn
	}
	if *schema != "" {
		cfg.DB.Schema = *schema
	}

	if err := confirmDestructiveMigration(action, *yes, cfg.DB.Dialect, cfg.DB.DSN); err != nil {
		log.Fatal(err)
	}

	auth, err := ezauth.New(cfg, "auth")
	if err != nil {
		log.Fatalf("failed to initialize ezauth: %v", err)
	}

	switch action {
	case "up":
		err = auth.Migrate()
	case "down":
		err = auth.MigrateDown()
	case "revert":
		err = auth.MigrateRevert()
	default:
		log.Fatalf("unknown migrate action %q (expected up, down, or revert)", action)
	}
	if err != nil {
		log.Fatalf("migrate %s failed: %v", action, err)
	}
	xlog.Info("migrate completed", "action", action)
}

// createAdmin bootstraps an admin-capable user: creates the account if it
// doesn't already exist, ensures the RBAC role exists, and grants it to the
// user. Safe to run repeatedly (e.g. in a Docker entrypoint on every boot).
func createAdmin(cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
	email := fs.String("email", "", "admin user's email (required)")
	password := fs.String("password", "", "admin user's password (required)")
	role := fs.String("role", "admin", "RBAC role to grant")
	fs.Parse(args)

	if *email == "" || *password == "" {
		log.Fatalf("usage: ezauthapi create-admin -email=<email> -password=<password> [-role=admin]")
	}

	auth, err := ezauth.New(cfg, "auth")
	if err != nil {
		log.Fatalf("failed to initialize ezauth: %v", err)
	}

	ctx := context.Background()
	user, err := auth.Service.Repo.UserGetByEmail(ctx, *email)
	if err != nil {
		user, err = auth.Service.UserCreate(ctx, &service.RequestBasicAuth{
			Email:    *email,
			Password: *password,
		})
		if err != nil {
			log.Fatalf("failed to create user: %v", err)
		}
	} else {
		xlog.Info("user already exists, ensuring role", "email", *email)
	}

	if _, err := auth.Service.Repo.RoleGetByName(ctx, *role); err != nil {
		if _, err := auth.Service.RoleCreate(ctx, *role, "bootstrap role"); err != nil {
			log.Fatalf("failed to create role %q: %v", *role, err)
		}
	}

	// "system" attributes this grant to the bootstrap CLI itself in the
	// audit log, since there's no authenticated admin user performing it --
	// this command IS the mechanism for creating the first admin.
	if err := auth.Service.UserRoleGrant(ctx, "system", user.ID, *role); err != nil {
		log.Fatalf("failed to grant role %q: %v", *role, err)
	}

	fmt.Printf("admin user ready: id=%s email=%s role=%s\n", user.ID, user.Email, *role)
}
