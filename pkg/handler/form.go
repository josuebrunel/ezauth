package handler

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/service"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
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
		Username:  r.FormValue("username"),
		Password:  r.FormValue("password"),
		FirstName: r.FormValue("first_name"),
		LastName:  r.FormValue("last_name"),
		Locale:    r.FormValue("locale"),
		Timezone:  r.FormValue("timezone"),
		Phone:     r.FormValue("phone"),
		AvatarURL: r.FormValue("avatar_url"),
		Nickname:  r.FormValue("nickname"),
		Data:      data,
	}

	if req.Password != r.FormValue("password_confirm") {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Register, "passwords do not match")
		return
	}

	// Pre-creation hook
	hookUser := &models.User{
		Email:     req.Email,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Locale:    req.Locale,
		Timezone:  req.Timezone,
		Phone:     req.Phone,
		AvatarURL: req.AvatarURL,
		Nickname:  req.Nickname,
	}
	if err := h.svc.Hook.BeforeUserCreated(r.Context(), hookUser); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Register, err.Error())
		return
	}

	user, err := h.svc.UserCreate(r.Context(), req)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Register, err.Error())
		return
	}

	if err := h.svc.Hook.AfterUserCreated(r.Context(), user); err != nil {
		xlog.Error("hook AfterUserCreated failed", "user_id", user.ID, "err", err)
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
		if errors.Is(err, service.ErrAccountLocked) || errors.Is(err, service.ErrAccountDisabled) {
			h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, err.Error())
			return
		}
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidCredentials.Error())
		return
	}

	deviceToken := ""
	if c, err := r.Cookie(h.svc.Cfg.TrustedDevice.CookieName); err == nil {
		deviceToken = c.Value
	}

	loginResp, err := h.svc.CompleteBasicLogin(r.Context(), user, deviceToken)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrCouldNotCreateToken.Error())
		return
	}

	if loginResp.MFARequired {
		h.Session.Put(r.Context(), sessionMFATokenKey, loginResp.MFAToken)
		http.Redirect(w, r, h.svc.Cfg.Pages.MFAVerify, http.StatusFound)
		return
	}

	if err := h.svc.Hook.AfterUserSignedIn(r.Context(), user); err != nil {
		xlog.Error("hook AfterUserSignedIn failed", "user_id", user.ID, "err", err)
	}

	h.setAuthCookies(r.Context(), loginResp.TokenResponse)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}

// FormMFALoginVerify completes a step-up login started by FormLogin when MFA is
// required, using the pending mfa token stashed server-side in the session.
func (h *Handler) FormMFALoginVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.MFAVerify, ErrInvalidRequestBody.Error())
		return
	}

	mfaToken, ok := h.Session.Get(r.Context(), sessionMFATokenKey).(string)
	if !ok || mfaToken == "" {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrNoPendingMFALogin.Error())
		return
	}

	code := r.FormValue("code")
	if code == "" {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.MFAVerify, ErrMFACodeRequired.Error())
		return
	}

	rememberDevice := r.FormValue("remember_device") != ""
	user, tokenResp, deviceToken, err := h.svc.MFALoginVerify(r.Context(), mfaToken, code, rememberDevice)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.MFAVerify, err.Error())
		return
	}

	h.Session.Remove(r.Context(), sessionMFATokenKey)

	if deviceToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     h.svc.Cfg.TrustedDevice.CookieName,
			Value:    deviceToken,
			Path:     "/",
			Expires:  time.Now().Add(h.svc.Cfg.TrustedDevice.TTL),
			HttpOnly: true,
			Secure:   strings.HasPrefix(h.svc.Cfg.BaseURL, "https://"),
			SameSite: http.SameSiteLaxMode,
		})
	}

	if err := h.svc.Hook.AfterUserSignedIn(r.Context(), user); err != nil {
		xlog.Error("hook AfterUserSignedIn failed", "user_id", user.ID, "err", err)
	}

	h.setAuthCookies(r.Context(), tokenResp)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}

// FormMFAEnroll begins TOTP MFA enrollment for the currently logged-in session user.
func (h *Handler) FormMFAEnroll(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrUnauthorized.Error())
		return
	}

	resp, err := h.svc.MFAEnroll(r.Context(), user)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, err.Error())
		return
	}

	h.Session.Put(r.Context(), sessionMFAEnrollSecretKey, resp.Secret)
	h.Session.Put(r.Context(), sessionMFAEnrollURLKey, resp.OTPAuthURL)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}

// FormMFAConfirm confirms TOTP MFA enrollment via form submission.
func (h *Handler) FormMFAConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ErrInvalidRequestBody.Error())
		return
	}

	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrUnauthorized.Error())
		return
	}

	code := r.FormValue("code")
	if code == "" {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ErrMFACodeRequired.Error())
		return
	}

	codes, err := h.svc.MFAConfirm(r.Context(), user, code)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, err.Error())
		return
	}

	if err := h.svc.Hook.AfterMFAEnabled(r.Context(), user); err != nil {
		xlog.Error("hook AfterMFAEnabled failed", "user_id", user.ID, "err", err)
	}

	h.Session.Remove(r.Context(), sessionMFAEnrollSecretKey)
	h.Session.Remove(r.Context(), sessionMFAEnrollURLKey)
	h.redirectWithSuccess(w, r, h.svc.Cfg.Redirects.AfterLogin, "mfa enabled; recovery codes: "+strings.Join(codes, ", "))
}

// FormMFADisable disables TOTP MFA via form submission.
func (h *Handler) FormMFADisable(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ErrInvalidRequestBody.Error())
		return
	}

	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrUnauthorized.Error())
		return
	}

	code := r.FormValue("code")
	if code == "" {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ErrMFACodeRequired.Error())
		return
	}

	if err := h.svc.MFADisable(r.Context(), user, code); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, err.Error())
		return
	}

	if err := h.svc.Hook.AfterMFADisabled(r.Context(), user); err != nil {
		xlog.Error("hook AfterMFADisabled failed", "user_id", user.ID, "err", err)
	}

	h.redirectWithSuccess(w, r, h.svc.Cfg.Redirects.AfterLogin, "mfa disabled")
}

// FormWebauthnRegisterBegin begins a WebAuthn/passkey registration ceremony for the
// current session user. Like the CSRF token endpoint, this returns JSON rather than
// redirecting: driving a WebAuthn ceremony requires client-side JavaScript regardless
// of whether the app otherwise uses cookies or Bearer tokens.
func (h *Handler) FormWebauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	creation, sessionKey, err := h.svc.WebauthnBeginRegistration(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, webauthnRegisterBeginResponse{CredentialCreation: creation, SessionKey: sessionKey}, nil)
}

// FormWebauthnRegisterFinish completes a registration ceremony for the current
// session user. The request body must be the browser's PublicKeyCredential
// response verbatim (from navigator.credentials.create()).
func (h *Handler) FormWebauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	sessionKey := r.URL.Query().Get("session_key")
	if sessionKey == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrWebauthnSessionKeyRequired)
		return
	}
	name := r.URL.Query().Get("name")

	cred, err := h.svc.WebauthnFinishRegistration(r.Context(), user, sessionKey, r, name)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, cred, nil)
}

// FormWebauthnCredentialsList lists the WebAuthn credentials registered for the
// current session user.
func (h *Handler) FormWebauthnCredentialsList(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	creds, err := h.svc.WebauthnCredentials(r.Context(), user.ID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, creds, nil)
}

// FormWebauthnCredentialDelete removes one of the current session user's WebAuthn credentials.
func (h *Handler) FormWebauthnCredentialDelete(w http.ResponseWriter, r *http.Request) {
	user, err := h.GetSessionUser(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, ErrUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	if id == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrWebauthnCredentialIDRequired)
		return
	}

	if err := h.svc.WebauthnDeleteCredential(r.Context(), user, id); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "credential deleted"}, nil)
}

// FormWebauthnLoginBegin begins a discoverable WebAuthn login ceremony for cookie-based clients.
func (h *Handler) FormWebauthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, sessionKey, err := h.svc.WebauthnBeginLogin(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, webauthnLoginBeginResponse{CredentialAssertion: assertion, SessionKey: sessionKey}, nil)
}

// FormWebauthnLoginFinish completes a WebAuthn login for cookie-based clients. On
// success it sets the session auth cookies (never exposing the raw tokens to
// client-side JavaScript) and returns a redirect URL for the page to navigate to.
func (h *Handler) FormWebauthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	sessionKey := r.URL.Query().Get("session_key")
	if sessionKey == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrWebauthnSessionKeyRequired)
		return
	}

	user, tokenResp, err := h.svc.WebauthnFinishLogin(r.Context(), sessionKey, r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusUnauthorized, err)
		return
	}

	if err := h.svc.Hook.AfterUserSignedIn(r.Context(), user); err != nil {
		xlog.Error("hook AfterUserSignedIn failed", "user_id", user.ID, "err", err)
	}

	h.setAuthCookies(r.Context(), tokenResp)
	WriteJSONResponse(w, http.StatusOK, map[string]string{"redirect": h.svc.Cfg.Redirects.AfterLogin}, nil)
}

// FormLogout handles user logout via form submission or link.
func (h *Handler) FormLogout(w http.ResponseWriter, r *http.Request) {
	if tokens, ok := h.GetSessionTokens(r.Context()); ok {
		if refreshToken, ok := tokens["refresh_token"]; ok && refreshToken != "" {
			_ = h.svc.TokenRevoke(r.Context(), refreshToken)
		}
	}

	// Fetch the user for the hook if possible
	if user, err := h.GetSessionUser(r.Context()); err == nil {
		if err := h.svc.Hook.AfterUserSignedOut(r.Context(), user); err != nil {
			xlog.Error("hook AfterUserSignedOut failed", "user_id", user.ID, "err", err)
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

// FormSMSOTPRequest handles the request for an SMS one-time login code via form.
func (h *Handler) FormSMSOTPRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidRequestBody.Error())
		return
	}

	req := service.RequestSMSOTP{
		Phone: r.FormValue("phone"),
	}

	if err := h.svc.SMSOTPRequest(r.Context(), req); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, err.Error())
		return
	}

	h.redirectWithSuccess(w, r, h.svc.Cfg.Pages.Login, "verification code sent")
}

// FormSMSOTPVerify handles login via an SMS one-time code submitted via form.
func (h *Handler) FormSMSOTPVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrInvalidRequestBody.Error())
		return
	}

	req := service.RequestSMSOTPVerify{
		Phone: r.FormValue("phone"),
		Code:  r.FormValue("code"),
	}

	tokenResp, err := h.svc.SMSOTPVerify(r.Context(), req)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, err.Error())
		return
	}

	if user, err := h.svc.Repo.UserGetByPhone(r.Context(), req.Phone); err == nil {
		if err := h.svc.Hook.AfterUserSignedIn(r.Context(), user); err != nil {
			xlog.Error("hook AfterUserSignedIn failed", "user_id", user.ID, "err", err)
		}
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

	// Fetch user to fire the hook (silently ignore if user not found)
	if user, err := h.svc.Repo.UserGetByEmail(r.Context(), req.Email); err == nil {
		if err := h.svc.Hook.AfterPasswordResetRequested(r.Context(), user); err != nil {
			xlog.Error("hook AfterPasswordResetRequested failed", "user_id", user.ID, "err", err)
		}
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

	// Fetch the user for the hook (silently ignore if not found)
	if token, err := h.svc.Repo.TokenGetByToken(r.Context(), req.Token); err == nil {
		if user, err := h.svc.Repo.UserGetByID(r.Context(), token.UserID); err == nil {
			if err := h.svc.Hook.AfterPasswordResetConfirmed(r.Context(), user); err != nil {
				xlog.Error("hook AfterPasswordResetConfirmed failed", "user_id", user.ID, "err", err)
			}
		}
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
// @Param provider path string true "OAuth2 Provider (google, github, facebook, discord, gitlab, slack, linkedin, spotify, or any registered custom provider)"
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
		Secure:   strings.HasPrefix(h.svc.Cfg.BaseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	url := conf.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// OAuth2Callback handles the callback from the OAuth2 provider.
// @Summary OAuth2 Callback
// @Description Handle the callback from the OAuth2 provider
// @Tags oauth2
// @Param provider path string true "OAuth2 Provider (google, github, facebook, discord, gitlab, slack, linkedin, spotify, or any registered custom provider)"
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
	if err != nil || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) == 0 {
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
		xlog.Error("oauth2 token exchange failed", "provider", provider, "error", err)
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrOAuth2Failed)
		return
	}

	userInfo, err := h.svc.OAuth2GetUserInfo(r.Context(), provider, token)
	if err != nil {
		xlog.Error("oauth2 get user info failed", "provider", provider, "error", err)
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrOAuth2Failed)
		return
	}

	user, err := h.svc.OAuth2Authenticate(r.Context(), provider, userInfo)
	if err != nil {
		xlog.Error("oauth2 authenticate failed", "provider", provider, "error", err)
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrOAuth2Failed)
		return
	}

	// Fire OAuth2 hooks.
	// Best-effort: if CreatedAt and UpdatedAt are equal (within a second), assume this is a new user.
	// For reliable detection, override these hooks in your implementation with your own logic.
	if user.CreatedAt.Sub(user.UpdatedAt) < time.Second && user.CreatedAt.Sub(user.UpdatedAt) > -time.Second {
		if err := h.svc.Hook.AfterOAuth2Created(r.Context(), user, provider); err != nil {
			xlog.Error("hook AfterOAuth2Created failed", "user_id", user.ID, "provider", provider, "err", err)
		}
	} else {
		if err := h.svc.Hook.AfterOAuth2SignedIn(r.Context(), user, provider); err != nil {
			xlog.Error("hook AfterOAuth2SignedIn failed", "user_id", user.ID, "provider", provider, "err", err)
		}
	}

	tokenResp, err := h.svc.TokenCreate(r.Context(), user)
	if err != nil {
		xlog.Error("oauth2 create token failed", "provider", provider, "error", err)
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrOAuth2Failed)
		return
	}

	if h.svc.Cfg.OAuth2.CallbackURL != "" {
		u, err := url.Parse(h.svc.Cfg.OAuth2.CallbackURL)
		if err != nil {
			xlog.Error("failed to parse callback url", "error", err)
			WriteJSONResponseError(w, http.StatusInternalServerError, fmt.Errorf("authentication failed"))
			return
		}
		// Use fragment (#) instead of query (?) — fragments are not sent to
		// the server in the HTTP request and are not logged by intermediaries.
		u.Fragment = fmt.Sprintf("access_token=%s&refresh_token=%s&expires_in=%d&token_type=%s",
			tokenResp.AccessToken,
			tokenResp.RefreshToken,
			tokenResp.ExpiresIn,
			tokenResp.TokenType,
		)
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}

	h.setAuthCookies(r.Context(), tokenResp)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}
