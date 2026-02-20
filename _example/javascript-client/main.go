package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/josuebrunel/ezauth"
	"github.com/josuebrunel/ezauth/pkg/config"
)

//go:embed static/*
var staticFiles embed.FS

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Initialize ezauth
	authApp, err := ezauth.New(&cfg, "auth")
	if err != nil {
		log.Fatalf("failed to init ezauth: %v", err)
	}

	// Run migrations
	if err := authApp.Migrate(); err != nil {
		log.Fatalf("failed to migrate: %v", err)
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Mount ezauth handler
	// ezauth internal router expects paths starting with "/auth" (because we passed "auth" to New)
	// so we use Handle to pass the full path.
	r.Handle("/auth/*", authApp.Handler)
	// Also handle swagger if we want it, but for now let's focus on auth.
	// r.Handle("/swagger/*", authApp.Handler)

	// Serve static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}

	fileServer := http.FileServer(http.FS(staticFS))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login.html", http.StatusFound)
	})

	r.Handle("/*", fileServer)

	log.Printf("Server starting on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, r); err != nil {
		log.Fatal(err)
	}
}
