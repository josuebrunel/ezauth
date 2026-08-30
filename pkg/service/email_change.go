package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/gopkg/xlog"
)

const emailChangeTokenTTL = 1 * time.Hour

var (
	ErrIncorrectPassword                = errors.New("incorrect password")
	ErrInvalidOrExpiredEmailChangeToken = errors.New("invalid or expired token")
)

// RequestEmailChange defines the parameters for initiating an email change.
type RequestEmailChange struct {
	CurrentPassword string `json:"current_password"`
	NewEmail        string `json:"new_email"`
}

// EmailChangeRequest initiates a guarded email-change flow for an
// already-authenticated user: it requires the current password to confirm
// intent, then emails a verification link to the *new* address. The account's
// email is not changed until EmailChangeConfirm is called with that link's
// token — the old address stays active in the meantime. A notice is also sent
// to the current address, since an unrequested email change is a classic
// account-takeover step.
func (a *Auth) EmailChangeRequest(ctx context.Context, user *models.User, req RequestEmailChange) error {
	if !verifyPassword(req.CurrentPassword, user.PasswordHash) {
		xlog.Debug("email change request failed: incorrect password", "user_id", user.ID)
		return ErrIncorrectPassword
	}

	newEmail := strings.ToLower(strings.TrimSpace(req.NewEmail))
	if err := validateEmail(newEmail); err != nil {
		return err
	}
	if newEmail == user.Email {
		return errors.New("new email must be different from the current email")
	}
	if _, err := a.Repo.UserGetByEmail(ctx, newEmail); err == nil {
		return ErrEmailAlreadyRegistered
	}

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		return err
	}

	token := &models.Token{
		UserID:    user.ID,
		Token:     tokenValue,
		TokenType: models.TokenTypeEmailChange,
		ExpiresAt: time.Now().Add(emailChangeTokenTTL),
		CreatedAt: time.Now(),
		Metadata:  models.JSONMap{"new_email": newEmail},
	}
	if _, err := a.Repo.TokenCreate(ctx, token); err != nil {
		xlog.Error("failed to save email change token", "user_id", user.ID, "err", err)
		return err
	}

	prefix := a.PathPrefix
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimSuffix(prefix, "/")
	}
	link := fmt.Sprintf("%s%s/email-change/confirm?token=%s", a.Cfg.BaseURL, prefix, tokenValue)

	newEmailData := EmailTemplateData{Link: link, Token: tokenValue, Email: newEmail, NewEmail: newEmail}
	subject := RenderTemplate(a.Cfg.EmailTemplates.EmailChangeSubject, newEmailData)
	body := RenderTemplate(a.Cfg.EmailTemplates.EmailChangeBody, newEmailData)
	if err := a.Mailer.Send(newEmail, subject, body); err != nil {
		xlog.Error("failed to send email change verification email", "user_id", user.ID, "err", err)
		return err
	}

	notifyData := EmailTemplateData{Email: user.Email, NewEmail: newEmail}
	notifySubject := RenderTemplate(a.Cfg.EmailTemplates.EmailChangeNotifySubject, notifyData)
	notifyBody := RenderTemplate(a.Cfg.EmailTemplates.EmailChangeNotifyBody, notifyData)
	if err := a.Mailer.Send(user.Email, notifySubject, notifyBody); err != nil {
		// The new-address verification email already went out; failing to notify
		// the old address is unfortunate but shouldn't block the flow.
		xlog.Warn("failed to send email change notice to current address", "user_id", user.ID, "err", err)
	}

	xlog.Info("email change requested", "user_id", user.ID)
	return nil
}

// EmailChangeConfirm completes a guarded email change: it validates the
// token emailed to the new address, applies the change, and — since a
// completed email change is as sensitive as a password reset — revokes all of
// the user's other sessions so they must re-authenticate everywhere.
func (a *Auth) EmailChangeConfirm(ctx context.Context, tokenValue string) (*models.User, error) {
	tok, err := a.Repo.TokenGetByToken(ctx, tokenValue)
	if err != nil || tok.TokenType != models.TokenTypeEmailChange {
		xlog.Debug("email change confirm failed: token not found or wrong type", "err", err)
		return nil, ErrInvalidOrExpiredEmailChangeToken
	}
	if tok.Revoked || time.Now().After(tok.ExpiresAt) {
		xlog.Debug("email change confirm failed: token expired or revoked", "token_id", tok.ID)
		return nil, ErrInvalidOrExpiredEmailChangeToken
	}

	newEmail, _ := tok.Metadata["new_email"].(string)
	if newEmail == "" {
		return nil, ErrInvalidOrExpiredEmailChangeToken
	}

	// Re-check: someone else may have registered this email since the request.
	if _, err := a.Repo.UserGetByEmail(ctx, newEmail); err == nil {
		return nil, ErrEmailAlreadyRegistered
	}

	user, err := a.Repo.UserGetByID(ctx, tok.UserID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	user.Email = newEmail
	user.EmailVerified = true
	user.EmailVerifiedAt = &now
	updated, err := a.Repo.UserUpdate(ctx, user)
	if err != nil {
		xlog.Error("failed to update user email", "user_id", user.ID, "err", err)
		return nil, err
	}

	if err := a.Repo.TokenRevoke(ctx, tok.ID); err != nil {
		xlog.Warn("failed to revoke email change token", "token_id", tok.ID, "err", err)
	}

	if err := a.Repo.TokenRevokeAllByUserID(ctx, updated.ID); err != nil {
		xlog.Error("failed to revoke sessions after email change", "user_id", updated.ID, "err", err)
	}

	xlog.Info("email changed", "user_id", updated.ID)
	return updated, nil
}
