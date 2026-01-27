package main

import (
	"log"

	"github.com/josuebrunel/ezauth"
	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/gopkg/xlog"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	xlog.Info("config", "cfg", cfg)
	auth, err := ezauth.New(&cfg, "auth")
	if err != nil {
		log.Fatalf("failed to initialize ezauth: %v", err)
	}

	// In standalone mode, we might want to run migrations automatically
	if err := auth.Migrate(); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	xlog.Info("starting server")
	auth.Handler.Run()
}
