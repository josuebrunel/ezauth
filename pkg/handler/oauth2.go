package handler

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func (h *Handler) OAuth2Login(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, fmt.Errorf("provider is required"))
		return
	}

	conf, err := h.svc.OAuth2GetConfig(provider)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	// Generate a random state for CSRF protection
	state := util.RandomString(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300, // 5 minutes
	})

	url := conf.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handler) OAuth2Callback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if provider == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, fmt.Errorf("provider is required"))
		return
	}

	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("oauth_state")
	if err != nil || state != cookie.Value {
		WriteJSONResponseError(w, http.StatusBadRequest, fmt.Errorf("invalid state"))
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, fmt.Errorf("code is required"))
		return
	}

	conf, err := h.svc.OAuth2GetConfig(provider)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	token, err := conf.Exchange(r.Context(), code)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("failed to exchange token: %w", err))
		return
	}

	userInfo, err := h.svc.OAuth2GetUserInfo(r.Context(), provider, token)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("failed to get user info: %w", err))
		return
	}

	user, err := h.svc.OAuth2Authenticate(r.Context(), provider, userInfo)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("failed to authenticate user: %w", err))
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("failed to create token: %w", err))
		return
	}

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}
