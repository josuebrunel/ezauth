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

var (
	ErrInvitationNotFound         = errors.New("invitation not found")
	ErrInvalidOrExpiredInvitation = errors.New("invalid or expired invitation")
	ErrEmailAlreadyRegistered     = errors.New("an account with this email already exists")
)

// RequestInvitation defines the parameters for issuing an invitation.
type RequestInvitation struct {
	Email string         `json:"email"`
	Roles string         `json:"roles"` // optional, comma-separated
	Data  map[string]any `json:"data"`  // optional, caller-defined (e.g. org id) opaque to ezauth
}

// RequestInvitationAccept defines the parameters for accepting an invitation.
// Email, Roles, and Data come from the invitation itself and cannot be
// overridden by the invitee — that's the point of an invite carrying a role.
type RequestInvitationAccept struct {
	Token     string `json:"token"`
	Password  string `json:"password"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Locale    string `json:"locale"`
	Timezone  string `json:"timezone"`
}

// InvitationInfo describes an invitation without exposing its raw token value.
type InvitationInfo struct {
	ID        string         `json:"id"`
	Email     string         `json:"email"`
	Roles     string         `json:"roles"`
	Data      map[string]any `json:"data,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
}

func invitationInfoFromToken(tok *models.Token) *InvitationInfo {
	email, _ := tok.Metadata["email"].(string)
	roles, _ := tok.Metadata["roles"].(string)
	data, _ := tok.Metadata["data"].(map[string]any)
	return &InvitationInfo{
		ID:        tok.ID,
		Email:     email,
		Roles:     roles,
		Data:      data,
		CreatedAt: tok.CreatedAt,
		ExpiresAt: tok.ExpiresAt,
	}
}

// InvitationCreate issues a new invitation on behalf of inviter, emailing
// invitee a link to accept it. Roles and Data are opaque to ezauth beyond
// being carried through to the created account at InvitationAccept — the
// caller decides what they mean (e.g. an org ID from a multi-tenancy layer
// built on top of ezauth).
func (a *Auth) InvitationCreate(ctx context.Context, inviter *models.User, req RequestInvitation) (*InvitationInfo, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	if _, err := a.Repo.UserGetByEmail(ctx, email); err == nil {
		return nil, ErrEmailAlreadyRegistered
	}

	tokenValue, err := a.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	metadata := models.JSONMap{
		"email":      email,
		"roles":      req.Roles,
		"inviter_id": inviter.ID,
	}
	if req.Data != nil {
		metadata["data"] = req.Data
	}

	now := time.Now()
	token := &models.Token{
		UserID:    inviter.ID,
		Token:     tokenValue,
		TokenType: models.TokenTypeInvitation,
		ExpiresAt: now.Add(a.Cfg.Invitation.TTL),
		CreatedAt: now,
		Metadata:  metadata,
	}
	created, err := a.Repo.TokenCreate(ctx, token)
	if err != nil {
		xlog.Error("failed to save invitation token", "inviter_id", inviter.ID, "err", err)
		return nil, err
	}

	prefix := a.PathPrefix
	if prefix != "" {
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		prefix = strings.TrimSuffix(prefix, "/")
	}
	link := fmt.Sprintf("%s%s/invitation/accept?token=%s", a.Cfg.BaseURL, prefix, tokenValue)

	data := EmailTemplateData{Link: link, Token: tokenValue, Email: email}
	subject := RenderTemplate(a.Cfg.EmailTemplates.InvitationSubject, data)
	body := RenderTemplate(a.Cfg.EmailTemplates.InvitationBody, data)
	if err := a.Mailer.Send(email, subject, body); err != nil {
		xlog.Error("failed to send invitation email", "inviter_id", inviter.ID, "err", err)
		return nil, err
	}

	xlog.Info("invitation created", "inviter_id", inviter.ID, "invitation_id", created.ID)
	return invitationInfoFromToken(created), nil
}

// InvitationPreview looks up a pending invitation by its raw token value,
// e.g. to prefill a registration form. It does not consume the invitation.
func (a *Auth) InvitationPreview(ctx context.Context, tokenValue string) (*InvitationInfo, error) {
	tok, err := a.getValidInvitationToken(ctx, tokenValue)
	if err != nil {
		return nil, err
	}
	return invitationInfoFromToken(tok), nil
}

func (a *Auth) getValidInvitationToken(ctx context.Context, tokenValue string) (*models.Token, error) {
	tok, err := a.Repo.TokenGetByToken(ctx, tokenValue)
	if err != nil || tok.TokenType != models.TokenTypeInvitation {
		return nil, ErrInvalidOrExpiredInvitation
	}
	if tok.Revoked || time.Now().After(tok.ExpiresAt) {
		return nil, ErrInvalidOrExpiredInvitation
	}
	return tok, nil
}

// InvitationAccept completes registration for an invitation: it creates the
// invitee's account with a pre-verified email and the roles/data the
// invitation carries, consumes the invitation, and logs the new user in.
func (a *Auth) InvitationAccept(ctx context.Context, req RequestInvitationAccept) (*models.User, *TokenResponse, error) {
	tok, err := a.getValidInvitationToken(ctx, req.Token)
	if err != nil {
		return nil, nil, err
	}

	email, _ := tok.Metadata["email"].(string)
	roles, _ := tok.Metadata["roles"].(string)
	data, _ := tok.Metadata["data"].(map[string]any)

	if _, err := a.Repo.UserGetByEmail(ctx, email); err == nil {
		return nil, nil, ErrEmailAlreadyRegistered
	}

	if err := a.validatePassword(req.Password); err != nil {
		return nil, nil, err
	}
	hash, err := a.UserHashPassword(req.Password)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	user := &models.User{
		Email:           email,
		Username:        strings.TrimSpace(req.Username),
		PasswordHash:    hash,
		Provider:        "local",
		EmailVerified:   true,
		EmailVerifiedAt: &now,
		FirstName:       strings.TrimSpace(req.FirstName),
		LastName:        strings.TrimSpace(req.LastName),
		Locale:          req.Locale,
		Timezone:        req.Timezone,
		Roles:           roles,
		UserMetadata:    data,
	}
	created, err := a.Repo.UserCreate(ctx, user)
	if err != nil {
		xlog.Error("failed to create user from invitation", "invitation_id", tok.ID, "err", err)
		return nil, nil, err
	}

	if err := a.Repo.TokenRevoke(ctx, tok.ID); err != nil {
		xlog.Warn("failed to revoke accepted invitation", "invitation_id", tok.ID, "err", err)
	}

	tokens, err := a.TokenCreate(ctx, created)
	if err != nil {
		return nil, nil, err
	}
	xlog.Info("invitation accepted", "invitation_id", tok.ID, "user_id", created.ID)
	return created, tokens, nil
}

// Invitations lists the pending invitations issued by inviter.
func (a *Auth) Invitations(ctx context.Context, inviterID string) ([]InvitationInfo, error) {
	tokens, err := a.Repo.TokenListByUserIDAndType(ctx, inviterID, models.TokenTypeInvitation)
	if err != nil {
		return nil, err
	}
	infos := make([]InvitationInfo, 0, len(tokens))
	for _, tok := range tokens {
		infos = append(infos, *invitationInfoFromToken(tok))
	}
	return infos, nil
}

// InvitationRevoke revokes one of inviter's pending invitations by its record ID.
func (a *Auth) InvitationRevoke(ctx context.Context, inviter *models.User, invitationID string) error {
	tok, err := a.Repo.TokenGetByID(ctx, invitationID)
	if err != nil || tok.UserID != inviter.ID || tok.TokenType != models.TokenTypeInvitation {
		return ErrInvitationNotFound
	}
	if err := a.Repo.TokenRevoke(ctx, tok.ID); err != nil {
		xlog.Error("failed to revoke invitation", "invitation_id", tok.ID, "err", err)
		return err
	}
	xlog.Info("invitation revoked", "inviter_id", inviter.ID, "invitation_id", tok.ID)
	return nil
}
