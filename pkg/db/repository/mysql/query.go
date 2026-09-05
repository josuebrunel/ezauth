package mysql

import (
	"context"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/mysql"
	"github.com/stephenafamo/bob/dialect/mysql/dialect"
	"github.com/stephenafamo/bob/dialect/mysql/dm"
	"github.com/stephenafamo/bob/dialect/mysql/im"
	"github.com/stephenafamo/bob/dialect/mysql/sm"
	"github.com/stephenafamo/bob/dialect/mysql/um"
)

type MysqlQuerier struct {
}

func (q *MysqlQuerier) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
	if user.ID == "" {
		user.ID = util.NewIDStripped()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TableUser,
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
			mysql.Arg(user.ID),
			mysql.Arg(user.Email),
			mysql.Arg(user.Username),
			mysql.Arg(user.PasswordHash),
			mysql.Arg(user.Provider),
			mysql.Arg(user.ProviderID),
			mysql.Arg(user.EmailVerified),
			mysql.Arg(user.AppMetadata),
			mysql.Arg(user.UserMetadata),
			mysql.Arg(user.FirstName),
			mysql.Arg(user.LastName),
			mysql.Arg(user.LastActiveAt),
			mysql.Arg(user.LastLoginAt),
			mysql.Arg(user.Locale),
			mysql.Arg(user.Timezone),
			mysql.Arg(user.EmailVerifiedAt),
			mysql.Arg(user.Phone),
			mysql.Arg(user.PhoneVerified),
			// New accounts always start active; see the sqlite querier for why
			// this isn't user.IsActive.
			mysql.Arg(true),
			mysql.Arg(user.AvatarURL),
			mysql.Arg(user.Nickname),
			mysql.Arg(user.Roles),
			mysql.Arg(user.MfaSecret),
			mysql.Arg(user.MfaEnabled),
			mysql.Arg(user.CreatedAt),
			mysql.Arg(user.UpdatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return mysql.Select(sm.From(models.TableUser), sm.Where(mysql.Quote(models.ColumnEmail).EQ(mysql.Arg(email))))
}

func (q *MysqlQuerier) QueryUserGetByUsername(ctx context.Context, username string) bob.Query {
	return mysql.Select(sm.From(models.TableUser), sm.Where(mysql.Quote(models.ColumnUsername).EQ(mysql.Arg(username))))
}

func (q *MysqlQuerier) QueryUserGetByPhone(ctx context.Context, phone string) bob.Query {
	return mysql.Select(sm.From(models.TableUser), sm.Where(mysql.Quote(models.ColumnPhone).EQ(mysql.Arg(phone))))
}

func (q *MysqlQuerier) QueryUserGetByID(ctx context.Context, id string) bob.Query {
	return mysql.Select(sm.From(models.TableUser), sm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryUserGetByProvider(ctx context.Context, provider, providerID string) bob.Query {
	return mysql.Select(
		sm.From(models.TableUser),
		sm.Where(
			mysql.Quote(models.ColumnProvider).EQ(mysql.Arg(provider)).
				And(mysql.Quote(models.ColumnProviderID).EQ(mysql.Arg(providerID))),
		),
	)
}

func (q *MysqlQuerier) QueryUserUpdate(ctx context.Context, user *models.User) bob.Query {
	qm := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(models.TableUser),
		um.SetCol(models.ColumnUpdatedAt).ToArg(time.Now().UTC()),
		um.Where(mysql.Quote("id").EQ(mysql.Arg(user.ID))),
	}

	if user.Email != "" {
		qm = append(qm, um.SetCol(models.ColumnEmail).ToArg(user.Email))
	}

	if user.Username != "" {
		qm = append(qm, um.SetCol(models.ColumnUsername).ToArg(user.Username))
	}

	if user.Provider != "" {
		qm = append(qm, um.SetCol(models.ColumnProvider).ToArg(user.Provider))
	}

	if user.PasswordHash != "" {
		qm = append(qm, um.SetCol(models.ColumnPasswordHash).ToArg(user.PasswordHash))
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

	return mysql.Update(qm...)
}

func (q *MysqlQuerier) QueryUserSetLockoutState(ctx context.Context, userID string, attempts int, lockedUntil *time.Time, isActive bool) bob.Query {
	return mysql.Update(
		um.Table(models.TableUser),
		um.SetCol(models.ColumnFailedLoginAttempts).ToArg(attempts),
		um.SetCol(models.ColumnLockedUntil).ToArg(lockedUntil),
		um.SetCol(models.ColumnIsActive).ToArg(isActive),
		um.SetCol(models.ColumnUpdatedAt).ToArg(time.Now().UTC()),
		um.Where(mysql.Quote("id").EQ(mysql.Arg(userID))),
	)
}

func (q *MysqlQuerier) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableUser), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryUsersList(ctx context.Context, filter models.UserListFilter, limit, offset int) bob.Query {
	mods := []bob.Mod[*dialect.SelectQuery]{
		sm.From(models.TableUser),
		sm.OrderBy(mysql.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(int64(limit)),
		sm.Offset(int64(offset)),
	}

	if filter.Search != "" {
		pattern := "%" + filter.Search + "%"
		mods = append(mods, sm.Where(
			mysql.Quote(models.ColumnEmail).Like(mysql.Arg(pattern)).
				Or(mysql.Quote(models.ColumnUsername).Like(mysql.Arg(pattern))),
		))
	}

	switch filter.Status {
	case models.UserStatusActive:
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnIsActive).EQ(mysql.Arg(true))))
	case models.UserStatusLocked:
		mods = append(mods,
			sm.Where(mysql.Quote(models.ColumnIsActive).EQ(mysql.Arg(false))),
			sm.Where(mysql.Quote(models.ColumnLockedUntil).IsNotNull()),
		)
	case models.UserStatusSuspended:
		mods = append(mods,
			sm.Where(mysql.Quote(models.ColumnIsActive).EQ(mysql.Arg(false))),
			sm.Where(mysql.Quote(models.ColumnLockedUntil).IsNull()),
		)
	}

	if filter.CreatedAfter != nil {
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnCreatedAt).GTE(mysql.Arg(*filter.CreatedAfter))))
	}
	if filter.CreatedBefore != nil {
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnCreatedAt).LTE(mysql.Arg(*filter.CreatedBefore))))
	}
	if filter.LastActiveAfter != nil {
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnLastActiveAt).GTE(mysql.Arg(*filter.LastActiveAfter))))
	}
	if filter.LastActiveBefore != nil {
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnLastActiveAt).LTE(mysql.Arg(*filter.LastActiveBefore))))
	}

	return mysql.Select(mods...)
}

func (q *MysqlQuerier) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
	if token.ID == "" {
		token.ID = util.NewIDStripped()
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TableToken,
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
			mysql.Arg(token.ID),
			mysql.Arg(token.UserID),
			mysql.Arg(token.Token),
			mysql.Arg(token.TokenType),
			mysql.Arg(token.ExpiresAt),
			mysql.Arg(token.CreatedAt),
			mysql.Arg(token.Revoked),
			mysql.Arg(token.Metadata),
		),
	)
}

// QueryTokenBatchInsert creates several tokens in a single multi-row INSERT.
func (q *MysqlQuerier) QueryTokenBatchInsert(ctx context.Context, tokens []*models.Token) bob.Query {
	rows := make([][]bob.Expression, len(tokens))
	for i, token := range tokens {
		if token.ID == "" {
			token.ID = util.NewIDStripped()
		}
		if token.CreatedAt.IsZero() {
			token.CreatedAt = time.Now().UTC()
		}
		rows[i] = []bob.Expression{
			mysql.Arg(token.ID),
			mysql.Arg(token.UserID),
			mysql.Arg(token.Token),
			mysql.Arg(token.TokenType),
			mysql.Arg(token.ExpiresAt),
			mysql.Arg(token.CreatedAt),
			mysql.Arg(token.Revoked),
			mysql.Arg(token.Metadata),
		}
	}
	return mysql.Insert(
		im.Into(models.TableToken,
			"id",
			models.ColumnUserID,
			models.ColumnToken,
			models.ColumnTokenType,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
			models.ColumnRevoked,
			models.ColumnMetadata,
		),
		im.Rows(rows...),
	)
}

func (q *MysqlQuerier) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return mysql.Select(sm.From(models.TableToken), sm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return mysql.Select(sm.From(models.TableToken), sm.Where(mysql.Quote(models.ColumnToken).EQ(mysql.Arg(token))))
}

func (q *MysqlQuerier) QueryTokenListByUserIDAndType(ctx context.Context, userID, tokenType string) bob.Query {
	return mysql.Select(
		sm.From(models.TableToken),
		sm.Where(
			mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID)).
				And(mysql.Quote(models.ColumnTokenType).EQ(mysql.Arg(tokenType))).
				And(mysql.Quote(models.ColumnRevoked).EQ(mysql.Arg(false))),
		),
		sm.OrderBy(mysql.Quote(models.ColumnCreatedAt)).Desc(),
	)
}

func (q *MysqlQuerier) QueryTokenListByUserID(ctx context.Context, userID string, limit int) bob.Query {
	return mysql.Select(
		sm.From(models.TableToken),
		sm.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))),
		sm.OrderBy(mysql.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(int64(limit)),
	)
}

func (q *MysqlQuerier) QueryTokenRevoke(ctx context.Context, id string) bob.Query {
	return mysql.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(mysql.Quote("id").EQ(mysql.Arg(id))),
	)
}

func (q *MysqlQuerier) QueryTokenRevokeAllByUserID(ctx context.Context, userID string) bob.Query {
	return mysql.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))),
	)
}

// QueryTokenRevokeFamily bulk-revokes every active refresh token sharing
// family_id (stored in the JSON Metadata column, see #118) in one UPDATE,
// instead of listing tokens and revoking them one at a time.
func (q *MysqlQuerier) QueryTokenRevokeFamily(ctx context.Context, userID, familyID string) bob.Query {
	return mysql.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))),
		um.Where(mysql.Quote(models.ColumnTokenType).EQ(mysql.Arg(models.TokenTypeRefresh))),
		um.Where(mysql.Quote(models.ColumnRevoked).EQ(mysql.Arg(false))),
		um.Where(mysql.Raw(models.ColumnMetadata+"->>'$.family_id' = ?", familyID)),
	)
}

// QueryTokenRevokeSessions bulk-revokes every active refresh-token session
// for a user in one UPDATE, optionally excluding one session (exceptID).
func (q *MysqlQuerier) QueryTokenRevokeSessions(ctx context.Context, userID, exceptID string) bob.Query {
	mods := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))),
		um.Where(mysql.Quote(models.ColumnTokenType).EQ(mysql.Arg(models.TokenTypeRefresh))),
		um.Where(mysql.Quote(models.ColumnRevoked).EQ(mysql.Arg(false))),
	}
	if exceptID != "" {
		mods = append(mods, um.Where(mysql.Quote("id").NE(mysql.Arg(exceptID))))
	}
	return mysql.Update(mods...)
}

func (q *MysqlQuerier) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableToken), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryWebauthnCredentialInsert(ctx context.Context, cred *models.WebauthnCredential) bob.Query {
	if cred.ID == "" {
		cred.ID = util.NewIDStripped()
	}
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TableWebauthnCredential,
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
			mysql.Arg(cred.ID),
			mysql.Arg(cred.UserID),
			mysql.Arg(cred.CredentialID),
			mysql.Arg(cred.PublicKey),
			mysql.Arg(cred.SignCount),
			mysql.Arg(cred.Transports),
			mysql.Arg(cred.AttestationType),
			mysql.Arg(cred.Name),
			mysql.Arg(cred.Data),
			mysql.Arg(cred.CreatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryWebauthnCredentialGetByID(ctx context.Context, id string) bob.Query {
	return mysql.Select(sm.From(models.TableWebauthnCredential), sm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryWebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) bob.Query {
	return mysql.Select(sm.From(models.TableWebauthnCredential), sm.Where(mysql.Quote(models.ColumnCredentialID).EQ(mysql.Arg(credentialID))))
}

func (q *MysqlQuerier) QueryWebauthnCredentialListByUserID(ctx context.Context, userID string) bob.Query {
	return mysql.Select(sm.From(models.TableWebauthnCredential), sm.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))))
}

func (q *MysqlQuerier) QueryWebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) bob.Query {
	return mysql.Update(
		um.Table(models.TableWebauthnCredential),
		um.SetCol(models.ColumnSignCount).ToArg(cred.SignCount),
		um.SetCol(models.ColumnData).ToArg(cred.Data),
		um.SetCol(models.ColumnName).ToArg(cred.Name),
		um.SetCol(models.ColumnLastUsedAt).ToArg(cred.LastUsedAt),
		um.Where(mysql.Quote("id").EQ(mysql.Arg(cred.ID))),
	)
}

func (q *MysqlQuerier) QueryWebauthnCredentialDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableWebauthnCredential), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryWebauthnChallengeInsert(ctx context.Context, ch *models.WebauthnChallenge) bob.Query {
	if ch.ID == "" {
		ch.ID = util.NewIDStripped()
	}
	if ch.CreatedAt.IsZero() {
		ch.CreatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TableWebauthnChallenge,
			"id",
			models.ColumnSessionKey,
			models.ColumnChallengeType,
			models.ColumnUserID,
			models.ColumnData,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
		),
		im.Values(
			mysql.Arg(ch.ID),
			mysql.Arg(ch.SessionKey),
			mysql.Arg(ch.ChallengeType),
			mysql.Arg(ch.UserID),
			mysql.Arg(ch.Data),
			mysql.Arg(ch.ExpiresAt),
			mysql.Arg(ch.CreatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryWebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) bob.Query {
	return mysql.Select(sm.From(models.TableWebauthnChallenge), sm.Where(mysql.Quote(models.ColumnSessionKey).EQ(mysql.Arg(sessionKey))))
}

func (q *MysqlQuerier) QueryWebauthnChallengeDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableWebauthnChallenge), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryAuditLogInsert(ctx context.Context, log *models.AuditLog) bob.Query {
	if log.ID == "" {
		log.ID = util.NewIDStripped()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TableAuditLog,
			"id",
			models.ColumnUserID,
			models.ColumnEventType,
			models.ColumnMetadata,
			models.ColumnCreatedAt,
		),
		im.Values(
			mysql.Arg(log.ID),
			mysql.Arg(log.UserID),
			mysql.Arg(log.EventType),
			mysql.Arg(log.Metadata),
			mysql.Arg(log.CreatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryAuditLogListByUserID(ctx context.Context, userID string, filter models.AuditLogFilter, limit, offset int) bob.Query {
	mods := []bob.Mod[*dialect.SelectQuery]{
		sm.From(models.TableAuditLog),
		sm.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))),
		sm.OrderBy(mysql.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(int64(limit)),
		sm.Offset(int64(offset)),
	}

	if filter.EventType != "" {
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnEventType).EQ(mysql.Arg(filter.EventType))))
	}
	if filter.Since != nil {
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnCreatedAt).GTE(mysql.Arg(*filter.Since))))
	}
	if filter.Until != nil {
		mods = append(mods, sm.Where(mysql.Quote(models.ColumnCreatedAt).LTE(mysql.Arg(*filter.Until))))
	}

	return mysql.Select(mods...)
}

func (q *MysqlQuerier) QueryRoleInsert(ctx context.Context, role *models.Role) bob.Query {
	if role.ID == "" {
		role.ID = util.NewIDStripped()
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TableRole,
			"id",
			models.ColumnName,
			models.ColumnDescription,
			models.ColumnCreatedAt,
		),
		im.Values(
			mysql.Arg(role.ID),
			mysql.Arg(role.Name),
			mysql.Arg(role.Description),
			mysql.Arg(role.CreatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryRoleGetByID(ctx context.Context, id string) bob.Query {
	return mysql.Select(sm.From(models.TableRole), sm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryRoleGetByName(ctx context.Context, name string) bob.Query {
	return mysql.Select(sm.From(models.TableRole), sm.Where(mysql.Quote(models.ColumnName).EQ(mysql.Arg(name))))
}

func (q *MysqlQuerier) QueryRolesList(ctx context.Context) bob.Query {
	return mysql.Select(sm.From(models.TableRole), sm.OrderBy(mysql.Quote(models.ColumnName)))
}

func (q *MysqlQuerier) QueryRoleDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableRole), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryPermissionInsert(ctx context.Context, permission *models.Permission) bob.Query {
	if permission.ID == "" {
		permission.ID = util.NewIDStripped()
	}
	if permission.CreatedAt.IsZero() {
		permission.CreatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TablePermission,
			"id",
			models.ColumnName,
			models.ColumnDescription,
			models.ColumnCreatedAt,
		),
		im.Values(
			mysql.Arg(permission.ID),
			mysql.Arg(permission.Name),
			mysql.Arg(permission.Description),
			mysql.Arg(permission.CreatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryPermissionGetByID(ctx context.Context, id string) bob.Query {
	return mysql.Select(sm.From(models.TablePermission), sm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryPermissionGetByName(ctx context.Context, name string) bob.Query {
	return mysql.Select(sm.From(models.TablePermission), sm.Where(mysql.Quote(models.ColumnName).EQ(mysql.Arg(name))))
}

func (q *MysqlQuerier) QueryPermissionsList(ctx context.Context) bob.Query {
	return mysql.Select(sm.From(models.TablePermission), sm.OrderBy(mysql.Quote(models.ColumnName)))
}

func (q *MysqlQuerier) QueryPermissionDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TablePermission), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

// QueryUserRoleInsert is idempotent: granting a role the user already
// holds is a no-op (INSERT IGNORE on the composite PK) rather than a
// constraint-violation error.
func (q *MysqlQuerier) QueryUserRoleInsert(ctx context.Context, userID, roleID string) bob.Query {
	return mysql.Insert(
		im.Into(models.TableUserRole, models.ColumnUserID, models.ColumnRoleID),
		im.Values(mysql.Arg(userID), mysql.Arg(roleID)),
		im.Ignore(),
	)
}

func (q *MysqlQuerier) QueryUserRoleDelete(ctx context.Context, userID, roleID string) bob.Query {
	return mysql.Delete(
		dm.From(models.TableUserRole),
		dm.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))),
		dm.Where(mysql.Quote(models.ColumnRoleID).EQ(mysql.Arg(roleID))),
	)
}

func (q *MysqlQuerier) QueryRolesByUserID(ctx context.Context, userID string) bob.Query {
	return mysql.Select(
		sm.Columns(
			mysql.Quote(models.TableRole, "id"),
			mysql.Quote(models.TableRole, models.ColumnName),
			mysql.Quote(models.TableRole, models.ColumnDescription),
			mysql.Quote(models.TableRole, models.ColumnCreatedAt),
		),
		sm.From(models.TableRole),
		sm.InnerJoin(models.TableUserRole).OnEQ(
			mysql.Quote(models.TableUserRole, models.ColumnRoleID),
			mysql.Quote(models.TableRole, "id"),
		),
		sm.Where(mysql.Quote(models.TableUserRole, models.ColumnUserID).EQ(mysql.Arg(userID))),
	)
}

// QueryRolePermissionInsert is idempotent: granting a permission the role
// already has is a no-op (INSERT IGNORE on the composite PK) rather than a
// constraint-violation error.
func (q *MysqlQuerier) QueryRolePermissionInsert(ctx context.Context, roleID, permissionID string) bob.Query {
	return mysql.Insert(
		im.Into(models.TableRolePermission, models.ColumnRoleID, models.ColumnPermissionID),
		im.Values(mysql.Arg(roleID), mysql.Arg(permissionID)),
		im.Ignore(),
	)
}

func (q *MysqlQuerier) QueryRolePermissionDelete(ctx context.Context, roleID, permissionID string) bob.Query {
	return mysql.Delete(
		dm.From(models.TableRolePermission),
		dm.Where(mysql.Quote(models.ColumnRoleID).EQ(mysql.Arg(roleID))),
		dm.Where(mysql.Quote(models.ColumnPermissionID).EQ(mysql.Arg(permissionID))),
	)
}

func (q *MysqlQuerier) QueryPermissionsByRoleID(ctx context.Context, roleID string) bob.Query {
	return mysql.Select(
		sm.Columns(
			mysql.Quote(models.TablePermission, "id"),
			mysql.Quote(models.TablePermission, models.ColumnName),
			mysql.Quote(models.TablePermission, models.ColumnDescription),
			mysql.Quote(models.TablePermission, models.ColumnCreatedAt),
		),
		sm.From(models.TablePermission),
		sm.InnerJoin(models.TableRolePermission).OnEQ(
			mysql.Quote(models.TableRolePermission, models.ColumnPermissionID),
			mysql.Quote(models.TablePermission, "id"),
		),
		sm.Where(mysql.Quote(models.TableRolePermission, models.ColumnRoleID).EQ(mysql.Arg(roleID))),
	)
}

// QueryPermissionsByUserID resolves the permissions a user holds transitively
// through every role granted to them: ezauth_user_roles -> ezauth_role_permissions
// -> ezauth_permissions. DISTINCT guards against double-counting a permission
// granted via more than one of the user's roles.
func (q *MysqlQuerier) QueryPermissionsByUserID(ctx context.Context, userID string) bob.Query {
	return mysql.Select(
		sm.Distinct(),
		sm.Columns(
			mysql.Quote(models.TablePermission, "id"),
			mysql.Quote(models.TablePermission, models.ColumnName),
			mysql.Quote(models.TablePermission, models.ColumnDescription),
			mysql.Quote(models.TablePermission, models.ColumnCreatedAt),
		),
		sm.From(models.TablePermission),
		sm.InnerJoin(models.TableRolePermission).OnEQ(
			mysql.Quote(models.TableRolePermission, models.ColumnPermissionID),
			mysql.Quote(models.TablePermission, "id"),
		),
		sm.InnerJoin(models.TableUserRole).OnEQ(
			mysql.Quote(models.TableUserRole, models.ColumnRoleID),
			mysql.Quote(models.TableRolePermission, models.ColumnRoleID),
		),
		sm.Where(mysql.Quote(models.TableUserRole, models.ColumnUserID).EQ(mysql.Arg(userID))),
	)
}

func (q *MysqlQuerier) QueryOrganizationInsert(ctx context.Context, org *models.Organization) bob.Query {
	if org.ID == "" {
		org.ID = util.NewIDStripped()
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now().UTC()
	}
	return mysql.Insert(
		im.Into(models.TableOrganization,
			"id",
			models.ColumnName,
			models.ColumnCreatedAt,
		),
		im.Values(
			mysql.Arg(org.ID),
			mysql.Arg(org.Name),
			mysql.Arg(org.CreatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryOrganizationGetByID(ctx context.Context, id string) bob.Query {
	return mysql.Select(sm.From(models.TableOrganization), sm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryOrganizationsList(ctx context.Context, limit, offset int) bob.Query {
	return mysql.Select(
		sm.From(models.TableOrganization),
		sm.OrderBy(mysql.Quote(models.ColumnName)),
		sm.Limit(int64(limit)),
		sm.Offset(int64(offset)),
	)
}

func (q *MysqlQuerier) QueryOrganizationDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableOrganization), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

// QueryOrgMemberUpsert inserts a (org, user) membership, or updates its
// role_id if the pair already exists (composite PK on org_id, user_id).
// mysql has no ON CONFLICT; ON DUPLICATE KEY UPDATE is the native equivalent.
func (q *MysqlQuerier) QueryOrgMemberUpsert(ctx context.Context, orgID, userID, roleID string) bob.Query {
	return mysql.Insert(
		im.Into(models.TableOrgMember, models.ColumnOrgID, models.ColumnUserID, models.ColumnRoleID),
		im.Values(mysql.Arg(orgID), mysql.Arg(userID), mysql.Arg(roleID)),
		im.OnDuplicateKeyUpdate(im.UpdateWithValues(models.ColumnRoleID)),
	)
}

func (q *MysqlQuerier) QueryOrgMemberRemove(ctx context.Context, orgID, userID string) bob.Query {
	return mysql.Delete(
		dm.From(models.TableOrgMember),
		dm.Where(mysql.Quote(models.ColumnOrgID).EQ(mysql.Arg(orgID))),
		dm.Where(mysql.Quote(models.ColumnUserID).EQ(mysql.Arg(userID))),
	)
}

// QueryOrgMembersByOrgID lists an org's members, joined with ezauth_roles for the role name.
func (q *MysqlQuerier) QueryOrgMembersByOrgID(ctx context.Context, orgID string) bob.Query {
	return mysql.Select(
		sm.Columns(
			mysql.Quote(models.TableOrgMember, models.ColumnOrgID),
			mysql.Quote(models.TableOrgMember, models.ColumnUserID),
			mysql.Quote(models.TableOrgMember, models.ColumnRoleID),
			mysql.Quote(models.TableRole, models.ColumnName).As(models.ColumnRoleName),
			mysql.Quote(models.TableOrgMember, models.ColumnCreatedAt),
		),
		sm.From(models.TableOrgMember),
		sm.InnerJoin(models.TableRole).OnEQ(
			mysql.Quote(models.TableRole, "id"),
			mysql.Quote(models.TableOrgMember, models.ColumnRoleID),
		),
		sm.Where(mysql.Quote(models.TableOrgMember, models.ColumnOrgID).EQ(mysql.Arg(orgID))),
	)
}

// QueryOrganizationsByUserID lists the organizations a user belongs to.
func (q *MysqlQuerier) QueryOrganizationsByUserID(ctx context.Context, userID string) bob.Query {
	return mysql.Select(
		sm.Columns(
			mysql.Quote(models.TableOrganization, "id"),
			mysql.Quote(models.TableOrganization, models.ColumnName),
			mysql.Quote(models.TableOrganization, models.ColumnCreatedAt),
		),
		sm.From(models.TableOrganization),
		sm.InnerJoin(models.TableOrgMember).OnEQ(
			mysql.Quote(models.TableOrgMember, models.ColumnOrgID),
			mysql.Quote(models.TableOrganization, "id"),
		),
		sm.Where(mysql.Quote(models.TableOrgMember, models.ColumnUserID).EQ(mysql.Arg(userID))),
	)
}
