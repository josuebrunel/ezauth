package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/gopkg/xlog"
)

type webauthnRegisterBeginResponse struct {
	*protocol.CredentialCreation
	SessionKey string `json:"session_key"`
}

type webauthnLoginBeginResponse struct {
	*protocol.CredentialAssertion
	SessionKey string `json:"session_key"`
}

func (h *Handler) contextUser(r *http.Request) (string, error) {
	userID, ok := r.Context().Value(ezmiddleware.UserContextKey).(string)
	if !ok {
		return "", ErrUserNotFoundInContext
	}
	return userID, nil
}

// WebauthnRegisterBegin begins a WebAuthn/passkey registration ceremony for the
// authenticated user.
// @Summary Begin WebAuthn registration
// @Description Generates WebAuthn credential creation options for the authenticated user
// @Tags webauthn
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[webauthnRegisterBeginResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/webauthn/register/begin [post]
func (h *Handler) WebauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	creation, sessionKey, err := h.svc.WebauthnBeginRegistration(r.Context(), user)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	WriteJSONResponse(w, http.StatusOK, webauthnRegisterBeginResponse{CredentialCreation: creation, SessionKey: sessionKey}, nil)
}

// WebauthnRegisterFinish completes a registration ceremony started by
// WebauthnRegisterBegin. The request body must be the browser's
// PublicKeyCredential response verbatim (from navigator.credentials.create()).
// @Summary Finish WebAuthn registration
// @Description Verifies the browser's attestation response and persists the new credential
// @Tags webauthn
// @Accept json
// @Produce json
// @Param session_key query string true "Session key returned by the begin step"
// @Param name query string false "Optional label for the credential"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[models.WebauthnCredential]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/webauthn/register/finish [post]
func (h *Handler) WebauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
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

// WebauthnCredentialsList lists the WebAuthn credentials registered for the
// authenticated user.
// @Summary List WebAuthn credentials
// @Tags webauthn
// @Produce json
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[[]models.WebauthnCredential]
// @Failure 500 {object} ApiResponse[string]
// @Router /auth/api/webauthn/credentials [get]
func (h *Handler) WebauthnCredentialsList(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}

	creds, err := h.svc.WebauthnCredentials(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, creds, nil)
}

// WebauthnCredentialDelete removes one of the authenticated user's WebAuthn credentials.
// @Summary Delete a WebAuthn credential
// @Tags webauthn
// @Produce json
// @Param id path string true "Credential record ID"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/webauthn/credentials/{id} [delete]
func (h *Handler) WebauthnCredentialDelete(w http.ResponseWriter, r *http.Request) {
	userID, err := h.contextUser(r)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, err)
		return
	}
	user, err := h.svc.Repo.UserGetByID(r.Context(), userID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
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

// WebauthnLoginBegin begins a discoverable (usernameless) WebAuthn login ceremony.
// @Summary Begin WebAuthn login
// @Description Generates WebAuthn credential request options for a discoverable (passkey) login
// @Tags webauthn
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[webauthnLoginBeginResponse]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/webauthn/login/begin [post]
func (h *Handler) WebauthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	assertion, sessionKey, err := h.svc.WebauthnBeginLogin(r.Context())
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}
	WriteJSONResponse(w, http.StatusOK, webauthnLoginBeginResponse{CredentialAssertion: assertion, SessionKey: sessionKey}, nil)
}

// WebauthnLoginFinish completes a login ceremony started by WebauthnLoginBegin. The
// request body must be the browser's PublicKeyCredential response verbatim (from
// navigator.credentials.get()).
// @Summary Finish WebAuthn login
// @Description Verifies the browser's assertion response and returns session tokens
// @Tags webauthn
// @Accept json
// @Produce json
// @Param session_key query string true "Session key returned by the begin step"
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[service.TokenResponse]
// @Failure 401 {object} ApiResponse[string]
// @Router /auth/api/webauthn/login/finish [post]
func (h *Handler) WebauthnLoginFinish(w http.ResponseWriter, r *http.Request) {
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

	WriteJSONResponse(w, http.StatusOK, tokenResp, nil)
}
