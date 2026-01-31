package handler

import (
	"net/http"
	"net/url"

	"github.com/josuebrunel/ezauth/pkg/service"
)

// FormRegister handles user registration via form submission.
func (h *Handler) FormRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Register, ErrInvalidRequestBody.Error())
		return
	}

	data := make(map[string]any)
	for key, values := range r.Form {
		if len(values) > 0 && len(key) > 5 && key[:5] == "meta_" {
			data[key[5:]] = values[0]
		}
	}

	req := &service.RequestBasicAuth{
		Email:     r.FormValue("email"),
		Password:  r.FormValue("password"),
		FirstName: r.FormValue("first_name"),
		LastName:  r.FormValue("last_name"),
		Locale:    r.FormValue("locale"),
		Timezone:  r.FormValue("timezone"),
		Roles:     r.FormValue("roles"),
		Data:      data,
	}

	if req.Password != r.FormValue("password_confirm") {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Register, "passwords do not match")
		return
	}

	user, err := h.svc.UserCreate(r.Context(), req)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Register, err.Error())
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Register, ErrCouldNotCreateToken.Error())
		return
	}

	h.setAuthCookies(r.Context(), tokenResp)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterRegister, http.StatusFound)
}

// FormLogin handles user login via form submission.
func (h *Handler) FormLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidRequestBody.Error())
		return
	}

	req := service.RequestBasicAuth{
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
	}

	user, err := h.svc.UserAuthenticate(r.Context(), req)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidCredentials.Error())
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrCouldNotCreateToken.Error())
		return
	}

	h.setAuthCookies(r.Context(), tokenResp)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}

// FormLogout handles user logout via form submission or link.
func (h *Handler) FormLogout(w http.ResponseWriter, r *http.Request) {
	// Try to get refresh token from session to revoke it
	if tokens, ok := h.GetSessionTokens(r.Context()); ok {
		if refreshToken, ok := tokens["refresh_token"]; ok && refreshToken != "" {
			_ = h.svc.TokenRevoke(r.Context(), refreshToken)
		}
	}

	h.clearAuthCookies(r.Context())
	http.Redirect(w, r, h.svc.Cfg.Pages.Login, http.StatusFound)
}

// FormPasswordlessRequest handles the request for a magic login link via form.
func (h *Handler) FormPasswordlessRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidRequestBody.Error())
		return
	}

	req := service.RequestPasswordless{
		Email: r.FormValue("email"),
	}

	if err := h.svc.PasswordlessRequest(r.Context(), req); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrCouldNotProcessPasswordless.Error())
		return
	}

	// Redirect back to login with success message
	u, _ := url.Parse(h.svc.Cfg.Pages.Login)
	q := u.Query()
	q.Set("success", "magic link sent")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// FormPasswordlessLogin handles login using a magic link token.
func (h *Handler) FormPasswordlessLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrTokenRequired.Error())
		return
	}

	tokenResp, err := h.svc.PasswordlessLogin(r.Context(), token)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, err.Error())
		return
	}

	h.setAuthCookies(r.Context(), tokenResp)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}

// FormPasswordResetRequest handles the request for a password reset link via form.
func (h *Handler) FormPasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidRequestBody.Error())
		return
	}

	req := service.RequestPasswordReset{
		Email: r.FormValue("email"),
	}

	if err := h.svc.PasswordResetRequest(r.Context(), req); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrCouldNotProcessPasswordReset.Error())
		return
	}

	u, _ := url.Parse(h.svc.Cfg.Pages.Login)
	q := u.Query()
	q.Set("success", "password reset link sent")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// FormPasswordResetConfirm handles the confirmation of a password reset via form.
func (h *Handler) FormPasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidRequestBody.Error())
		return
	}

	req := service.RequestPasswordResetConfirm{
		Token:    r.FormValue("token"),
		Password: r.FormValue("password"),
	}

	if err := h.svc.PasswordResetConfirm(r.Context(), req); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, err.Error())
		return
	}

	u, _ := url.Parse(h.svc.Cfg.Pages.Login)
	q := u.Query()
	q.Set("success", "password has been reset successfully")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *Handler) redirectWithError(w http.ResponseWriter, r *http.Request, target string, errMsg string) {
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", errMsg)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
