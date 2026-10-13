package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/josuebrunel/gopkg/xlog"
)

var (
	ErrInvitationNotFound         = errors.New("invitation not found")
	ErrInvalidOrExpiredInvitation = errors.New("invalid or expired invitation")
	ErrEmailAlreadyRegistered     = errors.New("an account with this email already exists")

	// ErrCannotGrantRole is returned by InvitationCreate when the inviter
	// requests a role they don't themselves hold, per the RBAC roles/
	// permissions tables (UserHasRole) -- the same source of truth every
	// admin gate (RequireRole/RequirePermission) checks. Without this
	// check, any authenticated user could self-invite with roles:"admin"
	// and be treated as admin by any app following the documented
	// caller.HasRole("admin")-via-RBAC pattern.
	ErrCannotGrantRole = errors.New("inviter is not authorized to grant one or more of the requested roles")
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
	InviterID string         `json:"inviter_id,omitempty"`
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
		InviterID: tok.UserID,
		Email:     email,
		Roles:     roles,
		Data:      data,
		CreatedAt: tok.CreatedAt,
		ExpiresAt: tok.ExpiresAt,
	}
}

// IssuedInvitation is a new invitation and the link its invitee uses to accept
// it. Link is not JSON-encoded, so it can't end up in an API response by
// accident: whoever holds it can accept the invitation.
type IssuedInvitation struct {
	InvitationInfo
	Link     string `json:"-"`
	EmailErr error  `json:"-"` // non-nil if the invitation email couldn't be sent
}

// InvitationIssue issues a new invitation on behalf of inviter and tries to
// email invitee a link to accept it. Unlike InvitationCreate it hands the link
// back, and a mail failure is reported in EmailErr instead of failing the call:
// the invitation exists either way, so a caller can still show or share the
// link when mail isn't delivered (no SMTP configured, an outage). Everything
// else, including the role rules below, is as for InvitationCreate.
// Data is opaque to ezauth beyond being carried
// through to the created account at InvitationAccept — the caller decides
// what it means (e.g. an org ID from a multi-tenancy layer built on top of
// ezauth). Roles is similarly carried through, but is not opaque: inviter
// must already hold every role requested, checked via the RBAC roles/
// permissions tables (UserHasRole) -- the same source of truth every admin
// gate checks -- so an invitation can never grant a role its creator
// doesn't have, and (unlike checking the legacy User.Roles field) a role
// granted this way is guaranteed to actually exist in RBAC by the time
// InvitationAccept grants it there too.
func (a *Auth) InvitationIssue(ctx context.Context, inviter *models.User, req RequestInvitation) (*IssuedInvitation, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	for _, role := range strings.Split(req.Roles, ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		has, err := a.UserHasRole(ctx, inviter.ID, role)
		if err != nil {
			xlog.Error("failed to check inviter's role", "inviter_id", inviter.ID, "role", role, "err", err)
			return nil, err
		}
		if !has {
			return nil, ErrCannotGrantRole
		}
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

	now := time.Now().UTC()
	token := &models.Token{
		UserID:    inviter.ID,
		Token:     util.HashToken(tokenValue),
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
	issued := &IssuedInvitation{InvitationInfo: *invitationInfoFromToken(created), Link: link}
	if err := a.Mailer.Send(email, subject, body); err != nil {
		xlog.Error("failed to send invitation email", "inviter_id", inviter.ID, "invitation_id", created.ID, "err", err)
		issued.EmailErr = err
	}

	xlog.Info("invitation created", "inviter_id", inviter.ID, "invitation_id", created.ID)
	return issued, nil
}

// InvitationCreate issues a new invitation on behalf of inviter, emailing
// invitee a link to accept it. If the email can't be sent the invitation is
// revoked again and the error returned, so a failed send doesn't leave an open
// invitation whose link nobody has. Use InvitationIssue to get the link back
// and keep the invitation when mail fails.
func (a *Auth) InvitationCreate(ctx context.Context, inviter *models.User, req RequestInvitation) (*InvitationInfo, error) {
	issued, err := a.InvitationIssue(ctx, inviter, req)
	if err != nil {
		return nil, err
	}
	if issued.EmailErr != nil {
		if err := a.Repo.TokenRevoke(ctx, issued.ID); err != nil {
			xlog.Error("failed to revoke an invitation whose email failed", "invitation_id", issued.ID, "err", err)
		}
		return nil, issued.EmailErr
	}
	return &issued.InvitationInfo, nil
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
	tok, err := a.Repo.TokenGetByToken(ctx, util.HashToken(tokenValue))
	if err != nil || tok.TokenType != models.TokenTypeInvitation {
		return nil, ErrInvalidOrExpiredInvitation
	}
	if tok.Revoked || time.Now().UTC().After(tok.ExpiresAt) {
		return nil, ErrInvalidOrExpiredInvitation
	}
	return tok, nil
}

// InvitationAccept completes registration for an invitation: it creates the
// invitee's account with a pre-verified email and the data the invitation
// carries, grants the invitation's roles via RBAC (UserRoleGrant, attributed
// to the original inviter) rather than writing the legacy User.Roles column,
// consumes the invitation, and logs the new user in.
func (a *Auth) InvitationAccept(ctx context.Context, req RequestInvitationAccept) (*models.User, *TokenResponse, error) {
	tok, err := a.getValidInvitationToken(ctx, req.Token)
	if err != nil {
		return nil, nil, err
	}

	// The consume itself is the guard, not a separate read-then-write --
	// see TokenRefresh's identical comment in auth.go. Without this,
	// concurrent acceptances of the same invitation could both pass the
	// (stale-read) validity check and both proceed to create an account
	// (see #206). Consumed here, before any of the account-creation work
	// below, rather than at the end where the original unconditional
	// revoke sat: by the time an unconditional revoke ran, a race-losing
	// request would already have created a user and granted roles, with
	// nothing left to safely undo.
	consumed, err := a.Repo.TokenConsume(ctx, tok.ID)
	if err != nil {
		return nil, nil, err
	}
	if !consumed {
		return nil, nil, ErrInvalidOrExpiredInvitation
	}

	email, _ := tok.Metadata["email"].(string)
	roles, _ := tok.Metadata["roles"].(string)
	inviterID, _ := tok.Metadata["inviter_id"].(string)
	data, _ := tok.Metadata["data"].(map[string]any)

	if _, err := a.Repo.UserGetByEmail(ctx, email); err == nil {
		return nil, nil, ErrEmailAlreadyRegistered
	}

	username := strings.TrimSpace(req.Username)
	if username != "" && !usernameRegex.MatchString(username) {
		return nil, nil, errors.New("username must be 3-30 characters: letters, numbers, underscores, hyphens")
	}

	if err := a.validatePassword(req.Password); err != nil {
		return nil, nil, err
	}
	hash, err := a.UserHashPassword(req.Password)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	user := &models.User{
		Email:           email,
		Username:        username,
		PasswordHash:    hash,
		Provider:        "local",
		EmailVerified:   true,
		EmailVerifiedAt: &now,
		FirstName:       strings.TrimSpace(req.FirstName),
		LastName:        strings.TrimSpace(req.LastName),
		Locale:          req.Locale,
		Timezone:        req.Timezone,
		UserMetadata:    data,
	}
	created, err := a.Repo.UserCreate(ctx, user)
	if err != nil {
		xlog.Error("failed to create user from invitation", "invitation_id", tok.ID, "err", err)
		return nil, nil, err
	}

	for _, role := range strings.Split(roles, ",") {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		if err := a.UserRoleGrant(ctx, inviterID, created.ID, role); err != nil {
			xlog.Error("failed to grant invitation role", "invitation_id", tok.ID, "user_id", created.ID, "role", role, "err", err)
			return nil, nil, err
		}
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

const (
	defaultInvitationsListLimit = 20
	maxInvitationsListLimit     = 100
)

// ListInvitationsOptions pages InvitationsAll.
type ListInvitationsOptions struct {
	Limit  int
	Offset int
}

// ListInvitationsResult is a page of open invitations.
type ListInvitationsResult struct {
	Invitations []InvitationInfo `json:"invitations"`
	HasMore     bool             `json:"has_more"`
}

// InvitationsAll lists the open invitations of every inviter, newest first.
// "Open" means not revoked: an accepted invitation is consumed, which revokes
// it, so it is gone from the list. Expired invitations are still listed (see
// InvitationInfo.ExpiresAt), so an admin can see and re-issue them. ezauth
// performs no authorization check here, same as UsersList; the caller must
// verify the requester may see every invitation.
func (a *Auth) InvitationsAll(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	limit := opts.Limit
	if limit <= 0 || limit > maxInvitationsListLimit {
		limit = defaultInvitationsListLimit
	}
	offset := max(opts.Offset, 0)

	tokens, hasMore, err := a.Repo.TokenListByType(ctx, models.TokenTypeInvitation, limit, offset)
	if err != nil {
		return nil, err
	}
	infos := make([]InvitationInfo, 0, len(tokens))
	for _, tok := range tokens {
		infos = append(infos, *invitationInfoFromToken(tok))
	}
	return &ListInvitationsResult{Invitations: infos, HasMore: hasMore}, nil
}

// InvitationRevokeByID revokes any invitation, whoever sent it. Unlike
// InvitationRevoke it checks no ownership, so an admin can cancel an
// invitation another admin sent, or one whose sender was deleted. It returns
// ErrInvitationNotFound for an unknown id or a token that isn't an invitation.
// ezauth performs no authorization check here; the caller must verify the
// requester may revoke invitations.
func (a *Auth) InvitationRevokeByID(ctx context.Context, invitationID string) error {
	tok, err := a.Repo.TokenGetByID(ctx, invitationID)
	if err != nil || tok.TokenType != models.TokenTypeInvitation {
		return ErrInvitationNotFound
	}
	if err := a.Repo.TokenRevoke(ctx, tok.ID); err != nil {
		xlog.Error("failed to revoke invitation", "invitation_id", tok.ID, "err", err)
		return err
	}
	xlog.Info("invitation revoked by id", "invitation_id", tok.ID)
	return nil
}
