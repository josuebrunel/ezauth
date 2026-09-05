package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	ezmiddleware "github.com/josuebrunel/ezauth/pkg/handler/middleware"
	"github.com/josuebrunel/gopkg/xlog"
)

// ImpersonateRequest defines the parameters for starting an impersonation session via the JSON API.
type ImpersonateRequest struct {
	TargetUserID string `json:"target_user_id"`
	// RefreshToken is the caller's own current refresh token. It is echoed back
	// unchanged as OriginalRefreshToken so the client can restore its own session
	// later via StopImpersonation, since the JSON API is stateless.
	RefreshToken string `json:"refresh_token"`
}

// ImpersonateResponse contains the target user's new tokens plus the admin's original
// tokens, so a JSON client can later call StopImpersonation to swap back.
type ImpersonateResponse struct {
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	ExpiresIn            int    `json:"expires_in"`
	TokenType            string `json:"token_type"`
	OriginalAccessToken  string `json:"original_access_token"`
	OriginalRefreshToken string `json:"original_refresh_token"`
	ImpersonatorID       string `json:"impersonator_id"`
	TargetUserID         string `json:"target_user_id"`
}

// StopImpersonationRequest defines the parameters for ending an impersonation session
// via the JSON API.
type StopImpersonationRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Impersonate mints a new token pair for a target user, acting on behalf of the
// currently authenticated user (the "admin"). ezauth performs no authorization check
// here: the caller is responsible for verifying the admin is allowed to impersonate
// (e.g. via admin.HasRole("admin")) before this endpoint is reached.
// @Summary Start impersonating a user
// @Description Mint tokens for a target user on behalf of the authenticated admin
// @Tags impersonation
// @Accept json
// @Produce json
// @Param request body ImpersonateRequest true "Impersonate Request"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[ImpersonateResponse]
// @Failure 400 {object} ApiResponse[string]
// @Failure 401 {object} ApiResponse[string]
// @Router /auth/api/impersonate [post]
func (h *Handler) Impersonate(w http.ResponseWriter, r *http.Request) {
	var req ImpersonateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if req.TargetUserID == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrTargetUserIDRequired)
		return
	}

	if _, err := GetImpersonatorID(r.Context()); err == nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrAlreadyImpersonating)
		return
	}

	adminID, ok := r.Context().Value(ezmiddleware.UserContextKey).(string)
	if !ok {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrUserNotFoundInContext)
		return
	}

	admin, err := h.svc.Repo.UserGetByID(r.Context(), adminID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusInternalServerError, ErrCouldNotRetrieveUser)
		return
	}

	tokenResp, err := h.svc.Impersonate(r.Context(), admin, req.TargetUserID)
	if err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	// Fetch the target for the hook and response (best-effort; Impersonate already
	// validated the target exists).
	target, err := h.svc.Repo.UserGetByID(r.Context(), req.TargetUserID)
	if err == nil {
		if err := h.svc.Hook.AfterImpersonationStarted(r.Context(), admin, target); err != nil {
			xlog.Error("hook AfterImpersonationStarted failed", "admin_id", admin.ID, "target_user_id", target.ID, "err", err)
		}
	}

	resp := ImpersonateResponse{
		AccessToken:          tokenResp.AccessToken,
		RefreshToken:         tokenResp.RefreshToken,
		ExpiresIn:            tokenResp.ExpiresIn,
		TokenType:            tokenResp.TokenType,
		OriginalAccessToken:  strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		OriginalRefreshToken: req.RefreshToken,
		ImpersonatorID:       admin.ID,
		TargetUserID:         req.TargetUserID,
	}
	WriteJSONResponse(w, http.StatusOK, resp, nil)
}

// StopImpersonation revokes an impersonation refresh token, ending that session.
// @Summary Stop impersonating a user
// @Description Revoke an impersonation refresh token
// @Tags impersonation
// @Accept json
// @Produce json
// @Param request body StopImpersonationRequest true "Stop Impersonation Request"
// @Security BearerAuth
// @Security ApiKeyAuth
// @Success 200 {object} ApiResponse[map[string]string]
// @Failure 400 {object} ApiResponse[string]
// @Router /auth/api/impersonate/stop [post]
func (h *Handler) StopImpersonation(w http.ResponseWriter, r *http.Request) {
	var req StopImpersonationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrInvalidRequestBody)
		return
	}

	if req.RefreshToken == "" {
		WriteJSONResponseError(w, http.StatusBadRequest, ErrRefreshTokenRequired)
		return
	}

	if err := h.svc.StopImpersonating(r.Context(), req.RefreshToken); err != nil {
		WriteJSONResponseError(w, http.StatusBadRequest, err)
		return
	}

	// Fetch the token for hook context (silently ignore if unavailable).
	if token, err := h.svc.Repo.TokenGetByToken(r.Context(), req.RefreshToken); err == nil {
		actorID, _ := token.Metadata["actor_id"].(string)
		target, targetErr := h.svc.Repo.UserGetByID(r.Context(), token.UserID)
		admin, adminErr := h.svc.Repo.UserGetByID(r.Context(), actorID)
		if targetErr == nil && adminErr == nil {
			if err := h.svc.Hook.AfterImpersonationEnded(r.Context(), admin, target); err != nil {
				xlog.Error("hook AfterImpersonationEnded failed", "admin_id", admin.ID, "target_user_id", target.ID, "err", err)
			}
		}
	}

	WriteJSONResponse(w, http.StatusOK, map[string]string{"message": "impersonation ended"}, nil)
}

// FormImpersonate handles starting an impersonation session via form submission
// (cookie-based session). Ends the request with an error redirect if the caller is
// already impersonating someone.
func (h *Handler) FormImpersonate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ErrInvalidRequestBody.Error())
		return
	}

	targetUserID := r.FormValue("target_user_id")
	if targetUserID == "" {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ErrTargetUserIDRequired.Error())
		return
	}

	admin, err := h.GetSessionUser(r.Context())
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Pages.Login, ErrUnauthorized.Error())
		return
	}

	if _, impersonating := h.IsImpersonating(r.Context()); impersonating {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, ErrAlreadyImpersonating.Error())
		return
	}

	tokenResp, err := h.svc.Impersonate(r.Context(), admin, targetUserID)
	if err != nil {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, err.Error())
		return
	}

	if target, err := h.svc.Repo.UserGetByID(r.Context(), targetUserID); err == nil {
		if err := h.svc.Hook.AfterImpersonationStarted(r.Context(), admin, target); err != nil {
			xlog.Error("hook AfterImpersonationStarted failed", "admin_id", admin.ID, "target_user_id", target.ID, "err", err)
		}
	}

	h.setImpersonationCookies(r.Context(), admin.ID, tokenResp)
	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}

// FormStopImpersonation handles ending an impersonation session via form submission,
// restoring the admin's own session (cookie-based swap-back).
func (h *Handler) FormStopImpersonation(w http.ResponseWriter, r *http.Request) {
	adminID, impersonating := h.IsImpersonating(r.Context())
	if !impersonating {
		h.redirectWithError(w, r, h.svc.Cfg.Redirects.AfterLogin, "not currently impersonating")
		return
	}

	target, _ := h.GetSessionUser(r.Context())

	if tokens, ok := h.GetSessionTokens(r.Context()); ok {
		if refreshToken, ok := tokens["refresh_token"]; ok && refreshToken != "" {
			_ = h.svc.StopImpersonating(r.Context(), refreshToken)
		}
	}

	restored := h.clearImpersonationCookies(r.Context())

	if target != nil {
		if admin, err := h.svc.Repo.UserGetByID(r.Context(), adminID); err == nil {
			if err := h.svc.Hook.AfterImpersonationEnded(r.Context(), admin, target); err != nil {
				xlog.Error("hook AfterImpersonationEnded failed", "admin_id", admin.ID, "target_user_id", target.ID, "err", err)
			}
		}
	}

	if !restored {
		h.clearAuthCookies(r.Context())
		http.Redirect(w, r, h.svc.Cfg.Pages.Login, http.StatusFound)
		return
	}

	http.Redirect(w, r, h.svc.Cfg.Redirects.AfterLogin, http.StatusFound)
}
