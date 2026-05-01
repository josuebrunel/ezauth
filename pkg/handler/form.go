package handler

import (
	"net/http"

	"fmt"

	"github.com/josuebrunel/ezauth/pkg/service"

	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/josuebrunel/ezauth/pkg/util"
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

	_ = service.CallHook(h.svc.Hooks.OnUserSignedIn, r.Context(), user)

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

	if tokens, ok := h.GetSessionTokens(r.Context()); ok {
		if userID, err := GetUserID(r.Context()); err == nil {
			if user, err := h.svc.Repo.UserGetByID(r.Context(), userID); err == nil {
				_ = service.CallHook(h.svc.Hooks.OnUserSignedOut, r.Context(), user)
			}
		}

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

	h.redirectWithSuccess(w, r, h.svc.Cfg.Pages.Login, "magic link sent")
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

	h.redirectWithSuccess(w, r, h.svc.Cfg.Pages.Login, "password reset link sent")
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

	h.redirectWithSuccess(w, r, h.svc.Cfg.Pages.Login, "password has been reset successfully")
}

func (h *Handler) redirectWithError(w http.ResponseWriter, r *http.Request, target string, errMsg string) {
	h.SetFlash(r.Context(), "error", errMsg)
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *Handler) redirectWithSuccess(w http.ResponseWriter, r *http.Request, target string, msg string) {
	h.SetFlash(r.Context(), "success", msg)
	http.Redirect(w, r, target, http.StatusFound)
}

// OAuth2Login redirects the user to the OAuth2 provider's login page.
// @Summary OAuth2 Login
// @Description Redirect to the OAuth2 provider login page
// @Tags oauth2
// @Param provider path string true "OAuth2 Provider (google, github, facebook)"
// @Security ApiKeyAuth
// @Success 307
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/oauth2/{provider}/login [get]
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

	state := util.RandomString(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})

	url := conf.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// OAuth2Callback handles the callback from the OAuth2 provider.
// @Summary OAuth2 Callback
// @Description Handle the callback from the OAuth2 provider
// @Tags oauth2
// @Param provider path string true "OAuth2 Provider (google, github, facebook)"
// @Param code query string true "Authorization Code"
// @Param state query string true "CSRF State"
// @Success 200 {object} ApiResponse[service.TokenResponse]
// @Success 302
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/oauth2/{provider}/callback [get]
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

	user, _, err := h.svc.OAuth2Authenticate(r.Context(), provider, userInfo)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("failed to authenticate user: %w", err))
		return
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("failed to create token: %w", err))
		return
	}

	if h.svc.Cfg.OAuth2.CallbackURL != "" {
		u, err := url.Parse(h.svc.Cfg.OAuth2.CallbackURL)
		if err != nil {
			WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("failed to parse callback url: %w", err))
			return
		}
		q := u.Query()
		q.Set("access_token", tokenResp.AccessToken)
		q.Set("refresh_token", tokenResp.RefreshToken)
		q.Set("expires_in", fmt.Sprintf("%d", tokenResp.ExpiresIn))
		q.Set("token_type", tokenResp.TokenType)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}

	h.setAuthCookies(r.Context(), tokenResp)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}
