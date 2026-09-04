package postgres

import (
	"context"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/dialect"
	"github.com/stephenafamo/bob/dialect/psql/dm"
	"github.com/stephenafamo/bob/dialect/psql/im"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/dialect/psql/um"
)

type PSQLQuerier struct {
}

func (q *PSQLQuerier) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
	if user.ID == "" {
		user.ID = util.NewID()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TableUser),
			"id",
			models.ColumnEmail,
			models.ColumnUsername,
			models.ColumnPasswordHash,
			models.ColumnProvider,
			models.ColumnProviderID,
			models.ColumnEmailVerified,
			models.ColumnAppMetadata,
			models.ColumnUserMetadata,
			models.ColumnFirstName,
			models.ColumnLastName,
			models.ColumnLastActiveAt,
			models.ColumnLastLoginAt,
			models.ColumnLocale,
			models.ColumnTimezone,
			models.ColumnEmailVerifiedAt,
			models.ColumnPhone,
			models.ColumnPhoneVerified,
			models.ColumnIsActive,
			models.ColumnAvatarURL,
			models.ColumnNickname,
			models.ColumnRoles,
			models.ColumnMfaSecret,
			models.ColumnMfaEnabled,
			models.ColumnCreatedAt,
			models.ColumnUpdatedAt,
		),
		im.Values(
			psql.Arg(user.ID),
			psql.Arg(user.Email),
			psql.Arg(user.Username),
			psql.Arg(user.PasswordHash),
			psql.Arg(user.Provider),
			psql.Arg(user.ProviderID),
			psql.Arg(user.EmailVerified),
			psql.Arg(user.AppMetadata),
			psql.Arg(user.UserMetadata),
			psql.Arg(user.FirstName),
			psql.Arg(user.LastName),
			psql.Arg(user.LastActiveAt),
			psql.Arg(user.LastLoginAt),
			psql.Arg(user.Locale),
			psql.Arg(user.Timezone),
			psql.Arg(user.EmailVerifiedAt),
			psql.Arg(user.Phone),
			psql.Arg(user.PhoneVerified),
			// New accounts always start active; see the sqlite querier for why
			// this isn't user.IsActive.
			psql.Arg(true),
			psql.Arg(user.AvatarURL),
			psql.Arg(user.Nickname),
			psql.Arg(user.Roles),
			psql.Arg(user.MfaSecret),
			psql.Arg(user.MfaEnabled),
			psql.Arg(user.CreatedAt),
			psql.Arg(user.UpdatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableUser)), sm.Where(psql.Quote(models.ColumnEmail).EQ(psql.Arg(email))))
}

func (q *PSQLQuerier) QueryUserGetByUsername(ctx context.Context, username string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableUser)), sm.Where(psql.Quote(models.ColumnUsername).EQ(psql.Arg(username))))
}

func (q *PSQLQuerier) QueryUserGetByPhone(ctx context.Context, phone string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableUser)), sm.Where(psql.Quote(models.ColumnPhone).EQ(psql.Arg(phone))))
}

func (q *PSQLQuerier) QueryUserGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableUser)), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryUserGetByProvider(ctx context.Context, provider, providerID string) bob.Query {
	return psql.Select(
		sm.From(psql.Quote(models.TableUser)),
		sm.Where(
			psql.Quote(models.ColumnProvider).EQ(psql.Arg(provider)).
				And(psql.Quote(models.ColumnProviderID).EQ(psql.Arg(providerID))),
		),
	)
}

func (q *PSQLQuerier) QueryUserUpdate(ctx context.Context, user *models.User) bob.Query {
	qm := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(psql.Quote(models.TableUser)),
		um.SetCol(models.ColumnUpdatedAt).ToArg(time.Now().UTC()),
		um.Where(psql.Quote("id").EQ(psql.Arg(user.ID))),
	}

	if user.Email != "" {
		qm = append(qm, um.SetCol(models.ColumnEmail).ToArg(user.Email))
	}

	if user.Username != "" {
		qm = append(qm, um.SetCol(models.ColumnUsername).ToArg(user.Username))
	}

	if user.PasswordHash != "" {
		qm = append(qm, um.SetCol(models.ColumnPasswordHash).ToArg(user.PasswordHash))
	}

	if user.Provider != "" {
		qm = append(qm, um.SetCol(models.ColumnProvider).ToArg(user.Provider))
	}

	if user.ProviderID != nil {
		qm = append(qm, um.SetCol(models.ColumnProviderID).ToArg(user.ProviderID))
	}

	qm = append(qm, um.SetCol(models.ColumnEmailVerified).ToArg(user.EmailVerified))

	if user.AppMetadata != nil {
		qm = append(qm, um.SetCol(models.ColumnAppMetadata).ToArg(user.AppMetadata))
	}

	if user.UserMetadata != nil {
		qm = append(qm, um.SetCol(models.ColumnUserMetadata).ToArg(user.UserMetadata))
	}

	if user.FirstName != "" {
		qm = append(qm, um.SetCol(models.ColumnFirstName).ToArg(user.FirstName))
	}

	if user.LastName != "" {
		qm = append(qm, um.SetCol(models.ColumnLastName).ToArg(user.LastName))
	}

	if user.LastActiveAt != nil {
		qm = append(qm, um.SetCol(models.ColumnLastActiveAt).ToArg(user.LastActiveAt))
	}

	if user.Locale != "" {
		qm = append(qm, um.SetCol(models.ColumnLocale).ToArg(user.Locale))
	}

	if user.Timezone != "" {
		qm = append(qm, um.SetCol(models.ColumnTimezone).ToArg(user.Timezone))
	}

	if user.EmailVerifiedAt != nil {
		qm = append(qm, um.SetCol(models.ColumnEmailVerifiedAt).ToArg(user.EmailVerifiedAt))
	}

	if user.LastLoginAt != nil {
		qm = append(qm, um.SetCol(models.ColumnLastLoginAt).ToArg(user.LastLoginAt))
	}

	if user.Phone != "" {
		qm = append(qm, um.SetCol(models.ColumnPhone).ToArg(user.Phone))
	}

	qm = append(qm, um.SetCol(models.ColumnPhoneVerified).ToArg(user.PhoneVerified))

	qm = append(qm, um.SetCol(models.ColumnIsActive).ToArg(user.IsActive))

	if user.AvatarURL != "" {
		qm = append(qm, um.SetCol(models.ColumnAvatarURL).ToArg(user.AvatarURL))
	}

	if user.Nickname != "" {
		qm = append(qm, um.SetCol(models.ColumnNickname).ToArg(user.Nickname))
	}

	if user.Roles != "" {
		qm = append(qm, um.SetCol(models.ColumnRoles).ToArg(user.Roles))
	}

	if user.MfaSecret != nil {
		qm = append(qm, um.SetCol(models.ColumnMfaSecret).ToArg(user.MfaSecret))
	}

	qm = append(qm, um.SetCol(models.ColumnMfaEnabled).ToArg(user.MfaEnabled))

	qm = append(qm, um.Returning("*"))

	return psql.Update(qm...)
}

func (q *PSQLQuerier) QueryUserCheckPasswordHash(ctx context.Context, email, passwordHash string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableUser)), sm.Where(psql.Quote(models.ColumnEmail).EQ(psql.Arg(email)).And(psql.Quote(models.ColumnPasswordHash).EQ(psql.Arg(passwordHash)))))
}

func (q *PSQLQuerier) QueryUserSetLockoutState(ctx context.Context, userID string, attempts int, lockedUntil *time.Time, isActive bool) bob.Query {
	return psql.Update(
		um.Table(psql.Quote(models.TableUser)),
		um.SetCol(models.ColumnFailedLoginAttempts).ToArg(attempts),
		um.SetCol(models.ColumnLockedUntil).ToArg(lockedUntil),
		um.SetCol(models.ColumnIsActive).ToArg(isActive),
		um.SetCol(models.ColumnUpdatedAt).ToArg(time.Now().UTC()),
		um.Where(psql.Quote("id").EQ(psql.Arg(userID))),
		um.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableUser)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryUsersList(ctx context.Context, filter models.UserListFilter, limit, offset int) bob.Query {
	mods := []bob.Mod[*dialect.SelectQuery]{
		sm.From(psql.Quote(models.TableUser)),
		sm.OrderBy(psql.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(limit),
		sm.Offset(offset),
	}

	if filter.Search != "" {
		pattern := "%" + filter.Search + "%"
		mods = append(mods, sm.Where(
			// ILIKE (not LIKE) for case-insensitive matching, matching sqlite/mysql's
			// default LIKE case-insensitivity.
			psql.Quote(models.ColumnEmail).OP("ILIKE", psql.Arg(pattern)).
				Or(psql.Quote(models.ColumnUsername).OP("ILIKE", psql.Arg(pattern))),
		))
	}

	switch filter.Status {
	case models.UserStatusActive:
		mods = append(mods, sm.Where(psql.Quote(models.ColumnIsActive).EQ(psql.Arg(true))))
	case models.UserStatusLocked:
		mods = append(mods,
			sm.Where(psql.Quote(models.ColumnIsActive).EQ(psql.Arg(false))),
			sm.Where(psql.Quote(models.ColumnLockedUntil).IsNotNull()),
		)
	case models.UserStatusSuspended:
		mods = append(mods,
			sm.Where(psql.Quote(models.ColumnIsActive).EQ(psql.Arg(false))),
			sm.Where(psql.Quote(models.ColumnLockedUntil).IsNull()),
		)
	}

	if filter.CreatedAfter != nil {
		mods = append(mods, sm.Where(psql.Quote(models.ColumnCreatedAt).GTE(psql.Arg(*filter.CreatedAfter))))
	}
	if filter.CreatedBefore != nil {
		mods = append(mods, sm.Where(psql.Quote(models.ColumnCreatedAt).LTE(psql.Arg(*filter.CreatedBefore))))
	}
	if filter.LastActiveAfter != nil {
		mods = append(mods, sm.Where(psql.Quote(models.ColumnLastActiveAt).GTE(psql.Arg(*filter.LastActiveAfter))))
	}
	if filter.LastActiveBefore != nil {
		mods = append(mods, sm.Where(psql.Quote(models.ColumnLastActiveAt).LTE(psql.Arg(*filter.LastActiveBefore))))
	}

	return psql.Select(mods...)
}

func (q *PSQLQuerier) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
	if token.ID == "" {
		token.ID = util.NewID()
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TableToken),
			"id",
			models.ColumnUserID,
			models.ColumnToken,
			models.ColumnTokenType,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
			models.ColumnRevoked,
			models.ColumnMetadata,
		),
		im.Values(
			psql.Arg(token.ID),
			psql.Arg(token.UserID),
			psql.Arg(token.Token),
			psql.Arg(token.TokenType),
			psql.Arg(token.ExpiresAt),
			psql.Arg(token.CreatedAt),
			psql.Arg(token.Revoked),
			psql.Arg(token.Metadata),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableToken)), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableToken)), sm.Where(psql.Quote(models.ColumnToken).EQ(psql.Arg(token))))
}

func (q *PSQLQuerier) QueryTokenListByUserIDAndType(ctx context.Context, userID, tokenType string) bob.Query {
	return psql.Select(
		sm.From(psql.Quote(models.TableToken)),
		sm.Where(
			psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID)).
				And(psql.Quote(models.ColumnTokenType).EQ(psql.Arg(tokenType))).
				And(psql.Quote(models.ColumnRevoked).EQ(psql.Arg(false))),
		),
	)
}

func (q *PSQLQuerier) QueryTokenListByUserID(ctx context.Context, userID string, limit int) bob.Query {
	return psql.Select(
		sm.From(psql.Quote(models.TableToken)),
		sm.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))),
		sm.OrderBy(psql.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(limit),
	)
}

func (q *PSQLQuerier) QueryTokenRevoke(ctx context.Context, id string) bob.Query {
	return psql.Update(
		um.Table(psql.Quote(models.TableToken)),
		um.SetCol(models.ColumnRevoked).To(true),
		um.Where(psql.Quote("id").EQ(psql.Arg(id))),
	)
}

func (q *PSQLQuerier) QueryTokenRevokeAllByUserID(ctx context.Context, userID string) bob.Query {
	return psql.Update(
		um.Table(psql.Quote(models.TableToken)),
		um.SetCol(models.ColumnRevoked).To(true),
		um.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))),
	)
}

// QueryTokenRevokeFamily bulk-revokes every active refresh token sharing
// family_id (stored in the JSONB Metadata column, see #118) in one UPDATE,
// instead of listing tokens and revoking them one at a time.
func (q *PSQLQuerier) QueryTokenRevokeFamily(ctx context.Context, userID, familyID string) bob.Query {
	return psql.Update(
		um.Table(psql.Quote(models.TableToken)),
		um.SetCol(models.ColumnRevoked).To(true),
		um.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))),
		um.Where(psql.Quote(models.ColumnTokenType).EQ(psql.Arg(models.TokenTypeRefresh))),
		um.Where(psql.Quote(models.ColumnRevoked).EQ(psql.Arg(false))),
		um.Where(psql.Raw(models.ColumnMetadata+"->>'family_id' = ?", familyID)),
	)
}

// QueryTokenRevokeSessions bulk-revokes every active refresh-token session
// for a user in one UPDATE, optionally excluding one session (exceptID).
func (q *PSQLQuerier) QueryTokenRevokeSessions(ctx context.Context, userID, exceptID string) bob.Query {
	mods := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(psql.Quote(models.TableToken)),
		um.SetCol(models.ColumnRevoked).To(true),
		um.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))),
		um.Where(psql.Quote(models.ColumnTokenType).EQ(psql.Arg(models.TokenTypeRefresh))),
		um.Where(psql.Quote(models.ColumnRevoked).EQ(psql.Arg(false))),
	}
	if exceptID != "" {
		mods = append(mods, um.Where(psql.Quote("id").NE(psql.Arg(exceptID))))
	}
	return psql.Update(mods...)
}

func (q *PSQLQuerier) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableToken)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryWebauthnCredentialInsert(ctx context.Context, cred *models.WebauthnCredential) bob.Query {
	if cred.ID == "" {
		cred.ID = util.NewID()
	}
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TableWebauthnCredential),
			"id",
			models.ColumnUserID,
			models.ColumnCredentialID,
			models.ColumnPublicKey,
			models.ColumnSignCount,
			models.ColumnTransports,
			models.ColumnAttestationType,
			models.ColumnName,
			models.ColumnData,
			models.ColumnCreatedAt,
		),
		im.Values(
			psql.Arg(cred.ID),
			psql.Arg(cred.UserID),
			psql.Arg(cred.CredentialID),
			psql.Arg(cred.PublicKey),
			psql.Arg(cred.SignCount),
			psql.Arg(cred.Transports),
			psql.Arg(cred.AttestationType),
			psql.Arg(cred.Name),
			psql.Arg(cred.Data),
			psql.Arg(cred.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryWebauthnCredentialGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableWebauthnCredential)), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryWebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableWebauthnCredential)), sm.Where(psql.Quote(models.ColumnCredentialID).EQ(psql.Arg(credentialID))))
}

func (q *PSQLQuerier) QueryWebauthnCredentialListByUserID(ctx context.Context, userID string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableWebauthnCredential)), sm.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))))
}

func (q *PSQLQuerier) QueryWebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) bob.Query {
	return psql.Update(
		um.Table(psql.Quote(models.TableWebauthnCredential)),
		um.SetCol(models.ColumnSignCount).ToArg(cred.SignCount),
		um.SetCol(models.ColumnData).ToArg(cred.Data),
		um.SetCol(models.ColumnName).ToArg(cred.Name),
		um.SetCol(models.ColumnLastUsedAt).ToArg(cred.LastUsedAt),
		um.Where(psql.Quote("id").EQ(psql.Arg(cred.ID))),
		um.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryWebauthnCredentialDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableWebauthnCredential)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryWebauthnChallengeInsert(ctx context.Context, ch *models.WebauthnChallenge) bob.Query {
	if ch.ID == "" {
		ch.ID = util.NewID()
	}
	if ch.CreatedAt.IsZero() {
		ch.CreatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TableWebauthnChallenge),
			"id",
			models.ColumnSessionKey,
			models.ColumnChallengeType,
			models.ColumnUserID,
			models.ColumnData,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
		),
		im.Values(
			psql.Arg(ch.ID),
			psql.Arg(ch.SessionKey),
			psql.Arg(ch.ChallengeType),
			psql.Arg(ch.UserID),
			psql.Arg(ch.Data),
			psql.Arg(ch.ExpiresAt),
			psql.Arg(ch.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryWebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableWebauthnChallenge)), sm.Where(psql.Quote(models.ColumnSessionKey).EQ(psql.Arg(sessionKey))))
}

func (q *PSQLQuerier) QueryWebauthnChallengeDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableWebauthnChallenge)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryAuditLogInsert(ctx context.Context, log *models.AuditLog) bob.Query {
	if log.ID == "" {
		log.ID = util.NewID()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TableAuditLog),
			"id",
			models.ColumnUserID,
			models.ColumnEventType,
			models.ColumnMetadata,
			models.ColumnCreatedAt,
		),
		im.Values(
			psql.Arg(log.ID),
			psql.Arg(log.UserID),
			psql.Arg(log.EventType),
			psql.Arg(log.Metadata),
			psql.Arg(log.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryAuditLogListByUserID(ctx context.Context, userID string, filter models.AuditLogFilter, limit, offset int) bob.Query {
	mods := []bob.Mod[*dialect.SelectQuery]{
		sm.From(psql.Quote(models.TableAuditLog)),
		sm.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))),
		sm.OrderBy(psql.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(limit),
		sm.Offset(offset),
	}

	if filter.EventType != "" {
		mods = append(mods, sm.Where(psql.Quote(models.ColumnEventType).EQ(psql.Arg(filter.EventType))))
	}
	if filter.Since != nil {
		mods = append(mods, sm.Where(psql.Quote(models.ColumnCreatedAt).GTE(psql.Arg(*filter.Since))))
	}
	if filter.Until != nil {
		mods = append(mods, sm.Where(psql.Quote(models.ColumnCreatedAt).LTE(psql.Arg(*filter.Until))))
	}

	return psql.Select(mods...)
}

func (q *PSQLQuerier) QueryRoleInsert(ctx context.Context, role *models.Role) bob.Query {
	if role.ID == "" {
		role.ID = util.NewID()
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TableRole),
			"id",
			models.ColumnName,
			models.ColumnDescription,
			models.ColumnCreatedAt,
		),
		im.Values(
			psql.Arg(role.ID),
			psql.Arg(role.Name),
			psql.Arg(role.Description),
			psql.Arg(role.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryRoleGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableRole)), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryRoleGetByName(ctx context.Context, name string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableRole)), sm.Where(psql.Quote(models.ColumnName).EQ(psql.Arg(name))))
}

func (q *PSQLQuerier) QueryRolesList(ctx context.Context) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableRole)), sm.OrderBy(psql.Quote(models.ColumnName)))
}

func (q *PSQLQuerier) QueryRoleDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableRole)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryPermissionInsert(ctx context.Context, permission *models.Permission) bob.Query {
	if permission.ID == "" {
		permission.ID = util.NewID()
	}
	if permission.CreatedAt.IsZero() {
		permission.CreatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TablePermission),
			"id",
			models.ColumnName,
			models.ColumnDescription,
			models.ColumnCreatedAt,
		),
		im.Values(
			psql.Arg(permission.ID),
			psql.Arg(permission.Name),
			psql.Arg(permission.Description),
			psql.Arg(permission.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryPermissionGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TablePermission)), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryPermissionGetByName(ctx context.Context, name string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TablePermission)), sm.Where(psql.Quote(models.ColumnName).EQ(psql.Arg(name))))
}

func (q *PSQLQuerier) QueryPermissionsList(ctx context.Context) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TablePermission)), sm.OrderBy(psql.Quote(models.ColumnName)))
}

func (q *PSQLQuerier) QueryPermissionDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TablePermission)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

// QueryUserRoleInsert is idempotent: granting a role the user already
// holds is a no-op (ON CONFLICT DO NOTHING on the composite PK) rather
// than a constraint-violation error.
func (q *PSQLQuerier) QueryUserRoleInsert(ctx context.Context, userID, roleID string) bob.Query {
	return psql.Insert(
		im.Into(psql.Quote(models.TableUserRole), models.ColumnUserID, models.ColumnRoleID),
		im.Values(psql.Arg(userID), psql.Arg(roleID)),
		im.OnConflict(models.ColumnUserID, models.ColumnRoleID).DoNothing(),
	)
}

func (q *PSQLQuerier) QueryUserRoleDelete(ctx context.Context, userID, roleID string) bob.Query {
	return psql.Delete(
		dm.From(psql.Quote(models.TableUserRole)),
		dm.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))),
		dm.Where(psql.Quote(models.ColumnRoleID).EQ(psql.Arg(roleID))),
	)
}

func (q *PSQLQuerier) QueryRolesByUserID(ctx context.Context, userID string) bob.Query {
	return psql.Select(
		sm.Columns(
			psql.Quote(models.TableRole, "id"),
			psql.Quote(models.TableRole, models.ColumnName),
			psql.Quote(models.TableRole, models.ColumnDescription),
			psql.Quote(models.TableRole, models.ColumnCreatedAt),
		),
		sm.From(psql.Quote(models.TableRole)),
		sm.InnerJoin(psql.Quote(models.TableUserRole)).OnEQ(
			psql.Quote(models.TableUserRole, models.ColumnRoleID),
			psql.Quote(models.TableRole, "id"),
		),
		sm.Where(psql.Quote(models.TableUserRole, models.ColumnUserID).EQ(psql.Arg(userID))),
	)
}

// QueryRolePermissionInsert is idempotent: granting a permission the role
// already has is a no-op (ON CONFLICT DO NOTHING on the composite PK)
// rather than a constraint-violation error.
func (q *PSQLQuerier) QueryRolePermissionInsert(ctx context.Context, roleID, permissionID string) bob.Query {
	return psql.Insert(
		im.Into(psql.Quote(models.TableRolePermission), models.ColumnRoleID, models.ColumnPermissionID),
		im.Values(psql.Arg(roleID), psql.Arg(permissionID)),
		im.OnConflict(models.ColumnRoleID, models.ColumnPermissionID).DoNothing(),
	)
}

func (q *PSQLQuerier) QueryRolePermissionDelete(ctx context.Context, roleID, permissionID string) bob.Query {
	return psql.Delete(
		dm.From(psql.Quote(models.TableRolePermission)),
		dm.Where(psql.Quote(models.ColumnRoleID).EQ(psql.Arg(roleID))),
		dm.Where(psql.Quote(models.ColumnPermissionID).EQ(psql.Arg(permissionID))),
	)
}

func (q *PSQLQuerier) QueryPermissionsByRoleID(ctx context.Context, roleID string) bob.Query {
	return psql.Select(
		sm.Columns(
			psql.Quote(models.TablePermission, "id"),
			psql.Quote(models.TablePermission, models.ColumnName),
			psql.Quote(models.TablePermission, models.ColumnDescription),
			psql.Quote(models.TablePermission, models.ColumnCreatedAt),
		),
		sm.From(psql.Quote(models.TablePermission)),
		sm.InnerJoin(psql.Quote(models.TableRolePermission)).OnEQ(
			psql.Quote(models.TableRolePermission, models.ColumnPermissionID),
			psql.Quote(models.TablePermission, "id"),
		),
		sm.Where(psql.Quote(models.TableRolePermission, models.ColumnRoleID).EQ(psql.Arg(roleID))),
	)
}

// QueryPermissionsByUserID resolves the permissions a user holds transitively
// through every role granted to them: ezauth_user_roles -> ezauth_role_permissions
// -> ezauth_permissions. DISTINCT guards against double-counting a permission
// granted via more than one of the user's roles.
func (q *PSQLQuerier) QueryPermissionsByUserID(ctx context.Context, userID string) bob.Query {
	return psql.Select(
		sm.Distinct(),
		sm.Columns(
			psql.Quote(models.TablePermission, "id"),
			psql.Quote(models.TablePermission, models.ColumnName),
			psql.Quote(models.TablePermission, models.ColumnDescription),
			psql.Quote(models.TablePermission, models.ColumnCreatedAt),
		),
		sm.From(psql.Quote(models.TablePermission)),
		sm.InnerJoin(psql.Quote(models.TableRolePermission)).OnEQ(
			psql.Quote(models.TableRolePermission, models.ColumnPermissionID),
			psql.Quote(models.TablePermission, "id"),
		),
		sm.InnerJoin(psql.Quote(models.TableUserRole)).OnEQ(
			psql.Quote(models.TableUserRole, models.ColumnRoleID),
			psql.Quote(models.TableRolePermission, models.ColumnRoleID),
		),
		sm.Where(psql.Quote(models.TableUserRole, models.ColumnUserID).EQ(psql.Arg(userID))),
	)
}

func (q *PSQLQuerier) QueryOrganizationInsert(ctx context.Context, org *models.Organization) bob.Query {
	if org.ID == "" {
		org.ID = util.NewID()
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now().UTC()
	}
	return psql.Insert(
		im.Into(psql.Quote(models.TableOrganization),
			"id",
			models.ColumnName,
			models.ColumnCreatedAt,
		),
		im.Values(
			psql.Arg(org.ID),
			psql.Arg(org.Name),
			psql.Arg(org.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryOrganizationGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableOrganization)), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryOrganizationsList(ctx context.Context, limit, offset int) bob.Query {
	return psql.Select(
		sm.From(psql.Quote(models.TableOrganization)),
		sm.OrderBy(psql.Quote(models.ColumnName)),
		sm.Limit(limit),
		sm.Offset(offset),
	)
}

func (q *PSQLQuerier) QueryOrganizationDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableOrganization)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

// QueryOrgMemberUpsert inserts a (org, user) membership, or updates its
// role_id if the pair already exists (composite PK on org_id, user_id).
func (q *PSQLQuerier) QueryOrgMemberUpsert(ctx context.Context, orgID, userID, roleID string) bob.Query {
	return psql.Insert(
		im.Into(psql.Quote(models.TableOrgMember), models.ColumnOrgID, models.ColumnUserID, models.ColumnRoleID),
		im.Values(psql.Arg(orgID), psql.Arg(userID), psql.Arg(roleID)),
		im.OnConflict(models.ColumnOrgID, models.ColumnUserID).DoUpdate(
			im.SetExcluded(models.ColumnRoleID),
		),
	)
}

func (q *PSQLQuerier) QueryOrgMemberRemove(ctx context.Context, orgID, userID string) bob.Query {
	return psql.Delete(
		dm.From(psql.Quote(models.TableOrgMember)),
		dm.Where(psql.Quote(models.ColumnOrgID).EQ(psql.Arg(orgID))),
		dm.Where(psql.Quote(models.ColumnUserID).EQ(psql.Arg(userID))),
	)
}

// QueryOrgMembersByOrgID lists an org's members, joined with ezauth_roles for the role name.
func (q *PSQLQuerier) QueryOrgMembersByOrgID(ctx context.Context, orgID string) bob.Query {
	return psql.Select(
		sm.Columns(
			psql.Quote(models.TableOrgMember, models.ColumnOrgID),
			psql.Quote(models.TableOrgMember, models.ColumnUserID),
			psql.Quote(models.TableOrgMember, models.ColumnRoleID),
			psql.Quote(models.TableRole, models.ColumnName).As(models.ColumnRoleName),
			psql.Quote(models.TableOrgMember, models.ColumnCreatedAt),
		),
		sm.From(psql.Quote(models.TableOrgMember)),
		sm.InnerJoin(psql.Quote(models.TableRole)).OnEQ(
			psql.Quote(models.TableRole, "id"),
			psql.Quote(models.TableOrgMember, models.ColumnRoleID),
		),
		sm.Where(psql.Quote(models.TableOrgMember, models.ColumnOrgID).EQ(psql.Arg(orgID))),
	)
}

// QueryOrganizationsByUserID lists the organizations a user belongs to.
func (q *PSQLQuerier) QueryOrganizationsByUserID(ctx context.Context, userID string) bob.Query {
	return psql.Select(
		sm.Columns(
			psql.Quote(models.TableOrganization, "id"),
			psql.Quote(models.TableOrganization, models.ColumnName),
			psql.Quote(models.TableOrganization, models.ColumnCreatedAt),
		),
		sm.From(psql.Quote(models.TableOrganization)),
		sm.InnerJoin(psql.Quote(models.TableOrgMember)).OnEQ(
			psql.Quote(models.TableOrgMember, models.ColumnOrgID),
			psql.Quote(models.TableOrganization, "id"),
		),
		sm.Where(psql.Quote(models.TableOrgMember, models.ColumnUserID).EQ(psql.Arg(userID))),
	)
}
