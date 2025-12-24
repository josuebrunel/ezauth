package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/josuebrunel/ezauth/handler"
	"github.com/josuebrunel/ezauth/service"
	"github.com/josuebrunel/ezauth/storage/memory"
)

func main() {
	// Initialize Adapter
	store := memory.New()

	// Initialize EzAuth Service
	authSvc := service.New(&service.Config{
		Storage: store,
		Debug:   true,
	})

	// Initialize Handler
	authHandler := handler.New(authSvc)

	// Handlers
	http.HandleFunc("/signup", authHandler.SignUpHandler)
	http.HandleFunc("/signin", authHandler.SignInHandler)
	http.HandleFunc("/magic-link", authHandler.MagicLinkHandler)
	http.HandleFunc("/verify-magic", authHandler.VerifyMagicLinkHandler)
	http.HandleFunc("/protected", authHandler.ProtectedHandler)

	fmt.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
