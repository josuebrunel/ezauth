package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/josuebrunel/ezauth"
	"github.com/josuebrunel/ezauth/pkg/config"
)

var templates map[string]*template.Template

func main() {
	// set env var
	os.Setenv("EZAUTH_API_KEY", "my-api-key")
	os.Setenv("EZAUTH_JWT_SECRET", "my-jwt-key")
	os.Setenv("EZAUTH_LOGIN_PAGE_URL", "/signin")
	os.Setenv("EZAUTH_REGISTER_PAGE_URL", "/signup")
	os.Setenv("EZAUTH_REDIRECT_AFTER_LOGIN", "/dashboard")
	os.Setenv("EZAUTH_REDIRECT_AFTER_REGISTER", "/signin")

	// initialize auth
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	auth, err := ezauth.New(&cfg, "")
	if err != nil {
		log.Fatalf("Failed to initialize auth: %v", err)
	}

	if err := auth.Migrate(); err != nil {
		log.Fatalf("Failed to migrate: %v", err)
	}
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// IMPORTANT: Add session middleware so that GetSessionUser works
	r.Use(auth.Handler.Session.LoadAndSave)

	// Initialize templates
	if err := initTemplates(); err != nil {
		log.Fatalf("Failed to initialize templates: %v", err)
	}

	r.Mount("/auth", auth.Handler)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
	})

	r.Get("/signin", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "signin.html", map[string]interface{}{
			"Title": "Sign In - Dashy",
		})
	})

	r.Get("/signup", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "signup.html", map[string]interface{}{
			"Title": "Sign Up - Dashy",
		})
	})

	r.Post("/profile", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.GetSessionUser(r.Context())
		if err != nil {
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		user.FirstName = r.FormValue("first_name")
		user.LastName = r.FormValue("last_name")

		// Call the service to update the user
		// Note: We need to access the Repository or Service directly
		// Since auth exposes Service, we use it.
		if _, err := auth.Service.UserUpdate(r.Context(), user); err != nil {
			http.Error(w, "Failed to update profile", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.GetSessionUser(r.Context())

		if err != nil {
			http.Redirect(w, r, "/signin", http.StatusSeeOther)
			return
		}

		renderTemplate(w, "dashboard.html", map[string]interface{}{
			"Title": "Dashboard - Dashy",
			"User":  user,
		})
	})

	fmt.Println("Server starting on :3000")
	http.ListenAndServe(":3000", r)
}

func initTemplates() error {
	templates = make(map[string]*template.Template)

	layoutPath := filepath.Join("views", "layout.html")
	pages := []string{"signin.html", "signup.html", "dashboard.html"}

	for _, page := range pages {
		pagePath := filepath.Join("views", page)
		tmpl, err := template.ParseFiles(layoutPath, pagePath)
		if err != nil {
			return err
		}
		templates[page] = tmpl
	}
	return nil
}

func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, ok := templates[name]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error rendering template %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
