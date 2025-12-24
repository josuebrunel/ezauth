package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/josuebrunel/ezauth/service"
)

type AuthHandler struct {
	Service *service.Auth
}

func New(s *service.Auth) *AuthHandler {
	return &AuthHandler{Service: s}
}

func (h *AuthHandler) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds service.EmailPasswordCredential
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.Service.SignUp(r.Context(), creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (h *AuthHandler) SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds service.EmailPasswordCredential
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, err := h.Service.SignIn(r.Context(), creds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "session_token",
		Value: session.Token,
		Path:  "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (h *AuthHandler) MagicLinkHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate requesting a magic link
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var data struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := h.Service.SendMagicLink(r.Context(), data.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "Magic link sent (check console)")
}

func (h *AuthHandler) VerifyMagicLinkHandler(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	token := r.URL.Query().Get("token")

	session, err := h.Service.VerifyMagicLink(r.Context(), email, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:  "session_token",
		Value: session.Token,
		Path:  "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (h *AuthHandler) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	token := h.Service.GetTokenFromRequest(r)
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	session, err := h.Service.ValidateSession(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Hello User %s! You are authenticated.", session.UserID)
}
