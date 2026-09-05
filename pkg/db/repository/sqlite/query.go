package sqlite

import (
	"context"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/josuebrunel/ezauth/pkg/util"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/sqlite"
	"github.com/stephenafamo/bob/dialect/sqlite/dialect"
	"github.com/stephenafamo/bob/dialect/sqlite/dm"
	"github.com/stephenafamo/bob/dialect/sqlite/im"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
	"github.com/stephenafamo/bob/dialect/sqlite/um"
)

type SqliteQuerier struct {
}

func (q *SqliteQuerier) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
	if user.ID == "" {
		user.ID = util.NewIDStripped()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
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
			sqlite.Arg(user.ID),
			sqlite.Arg(user.Email),
			sqlite.Arg(user.Username),
			sqlite.Arg(user.PasswordHash),
			sqlite.Arg(user.Provider),
			sqlite.Arg(user.ProviderID),
			sqlite.Arg(user.EmailVerified),
			sqlite.Arg(user.AppMetadata),
			sqlite.Arg(user.UserMetadata),
			sqlite.Arg(user.FirstName),
			sqlite.Arg(user.LastName),
			sqlite.Arg(user.LastActiveAt),
			sqlite.Arg(user.LastLoginAt),
			sqlite.Arg(user.Locale),
			sqlite.Arg(user.Timezone),
			sqlite.Arg(user.EmailVerifiedAt),
			sqlite.Arg(user.Phone),
			sqlite.Arg(user.PhoneVerified),
			// New accounts always start active; deactivation is only ever a
			// subsequent action (lockout, admin suspension), never part of
			// creation, so this doesn't depend on the zero-valued bool the
			// caller's struct literal happens to carry.
			sqlite.Arg(true),
			sqlite.Arg(user.AvatarURL),
			sqlite.Arg(user.Nickname),
			sqlite.Arg(user.Roles),
			sqlite.Arg(user.MfaSecret),
			sqlite.Arg(user.MfaEnabled),
			sqlite.Arg(user.CreatedAt),
			sqlite.Arg(user.UpdatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return sqlite.Select(sm.From(models.TableUser), sm.Where(sqlite.Quote(models.ColumnEmail).EQ(sqlite.Arg(email))))
}

func (q *SqliteQuerier) QueryUserGetByUsername(ctx context.Context, username string) bob.Query {
	return sqlite.Select(sm.From(models.TableUser), sm.Where(sqlite.Quote(models.ColumnUsername).EQ(sqlite.Arg(username))))
}

func (q *SqliteQuerier) QueryUserGetByPhone(ctx context.Context, phone string) bob.Query {
	return sqlite.Select(sm.From(models.TableUser), sm.Where(sqlite.Quote(models.ColumnPhone).EQ(sqlite.Arg(phone))))
}

func (q *SqliteQuerier) QueryUserGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableUser), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryUserGetByProvider(ctx context.Context, provider, providerID string) bob.Query {
	return sqlite.Select(
		sm.From(models.TableUser),
		sm.Where(
			sqlite.Quote(models.ColumnProvider).EQ(sqlite.Arg(provider)).
				And(sqlite.Quote(models.ColumnProviderID).EQ(sqlite.Arg(providerID))),
		),
	)
}

func (q *SqliteQuerier) QueryUserUpdate(ctx context.Context, user *models.User) bob.Query {
	qm := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(models.TableUser),
		um.SetCol(models.ColumnUpdatedAt).ToArg(time.Now().UTC()),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(user.ID))),
		um.Returning("*"),
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

	return sqlite.Update(qm...)
}

func (q *SqliteQuerier) QueryUserSetLockoutState(ctx context.Context, userID string, attempts int, lockedUntil *time.Time, isActive bool) bob.Query {
	return sqlite.Update(
		um.Table(models.TableUser),
		um.SetCol(models.ColumnFailedLoginAttempts).ToArg(attempts),
		um.SetCol(models.ColumnLockedUntil).ToArg(lockedUntil),
		um.SetCol(models.ColumnIsActive).ToArg(isActive),
		um.SetCol(models.ColumnUpdatedAt).ToArg(time.Now().UTC()),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(userID))),
		um.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableUser), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryUsersList(ctx context.Context, filter models.UserListFilter, limit, offset int) bob.Query {
	mods := []bob.Mod[*dialect.SelectQuery]{
		sm.From(models.TableUser),
		sm.OrderBy(sqlite.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(limit),
		sm.Offset(offset),
	}

	if filter.Search != "" {
		pattern := "%" + filter.Search + "%"
		mods = append(mods, sm.Where(
			sqlite.Quote(models.ColumnEmail).Like(sqlite.Arg(pattern)).
				Or(sqlite.Quote(models.ColumnUsername).Like(sqlite.Arg(pattern))),
		))
	}

	switch filter.Status {
	case models.UserStatusActive:
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnIsActive).EQ(sqlite.Arg(true))))
	case models.UserStatusLocked:
		mods = append(mods,
			sm.Where(sqlite.Quote(models.ColumnIsActive).EQ(sqlite.Arg(false))),
			sm.Where(sqlite.Quote(models.ColumnLockedUntil).IsNotNull()),
		)
	case models.UserStatusSuspended:
		mods = append(mods,
			sm.Where(sqlite.Quote(models.ColumnIsActive).EQ(sqlite.Arg(false))),
			sm.Where(sqlite.Quote(models.ColumnLockedUntil).IsNull()),
		)
	}

	if filter.CreatedAfter != nil {
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnCreatedAt).GTE(sqlite.Arg(*filter.CreatedAfter))))
	}
	if filter.CreatedBefore != nil {
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnCreatedAt).LTE(sqlite.Arg(*filter.CreatedBefore))))
	}
	if filter.LastActiveAfter != nil {
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnLastActiveAt).GTE(sqlite.Arg(*filter.LastActiveAfter))))
	}
	if filter.LastActiveBefore != nil {
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnLastActiveAt).LTE(sqlite.Arg(*filter.LastActiveBefore))))
	}

	return sqlite.Select(mods...)
}

func (q *SqliteQuerier) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
	if token.ID == "" {
		token.ID = util.NewIDStripped()
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
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
			sqlite.Arg(token.ID),
			sqlite.Arg(token.UserID),
			sqlite.Arg(token.Token),
			sqlite.Arg(token.TokenType),
			sqlite.Arg(token.ExpiresAt),
			sqlite.Arg(token.CreatedAt),
			sqlite.Arg(token.Revoked),
			sqlite.Arg(token.Metadata),
		),
		im.Returning("*"),
	)
}

// QueryTokenBatchInsert creates several tokens in a single multi-row INSERT.
func (q *SqliteQuerier) QueryTokenBatchInsert(ctx context.Context, tokens []*models.Token) bob.Query {
	rows := make([][]bob.Expression, len(tokens))
	for i, token := range tokens {
		if token.ID == "" {
			token.ID = util.NewIDStripped()
		}
		if token.CreatedAt.IsZero() {
			token.CreatedAt = time.Now().UTC()
		}
		rows[i] = []bob.Expression{
			sqlite.Arg(token.ID),
			sqlite.Arg(token.UserID),
			sqlite.Arg(token.Token),
			sqlite.Arg(token.TokenType),
			sqlite.Arg(token.ExpiresAt),
			sqlite.Arg(token.CreatedAt),
			sqlite.Arg(token.Revoked),
			sqlite.Arg(token.Metadata),
		}
	}
	return sqlite.Insert(
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

func (q *SqliteQuerier) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableToken), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return sqlite.Select(sm.From(models.TableToken), sm.Where(sqlite.Quote(models.ColumnToken).EQ(sqlite.Arg(token))))
}

func (q *SqliteQuerier) QueryTokenListByUserIDAndType(ctx context.Context, userID, tokenType string) bob.Query {
	return sqlite.Select(
		sm.From(models.TableToken),
		sm.Where(
			sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID)).
				And(sqlite.Quote(models.ColumnTokenType).EQ(sqlite.Arg(tokenType))).
				And(sqlite.Quote(models.ColumnRevoked).EQ(sqlite.Arg(false))),
		),
		sm.OrderBy(sqlite.Quote(models.ColumnCreatedAt)).Desc(),
	)
}

func (q *SqliteQuerier) QueryTokenListByUserID(ctx context.Context, userID string, limit int) bob.Query {
	return sqlite.Select(
		sm.From(models.TableToken),
		sm.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))),
		sm.OrderBy(sqlite.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(limit),
	)
}

func (q *SqliteQuerier) QueryTokenRevoke(ctx context.Context, id string) bob.Query {
	return sqlite.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))),
	)
}

func (q *SqliteQuerier) QueryTokenRevokeAllByUserID(ctx context.Context, userID string) bob.Query {
	return sqlite.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))),
	)
}

// QueryTokenRevokeFamily bulk-revokes every active refresh token sharing
// family_id (stored in the JSON Metadata column, see #118) in one UPDATE,
// instead of listing tokens and revoking them one at a time.
func (q *SqliteQuerier) QueryTokenRevokeFamily(ctx context.Context, userID, familyID string) bob.Query {
	return sqlite.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))),
		um.Where(sqlite.Quote(models.ColumnTokenType).EQ(sqlite.Arg(models.TokenTypeRefresh))),
		um.Where(sqlite.Quote(models.ColumnRevoked).EQ(sqlite.Arg(false))),
		um.Where(sqlite.Raw("json_extract("+models.ColumnMetadata+", '$.family_id') = ?", familyID)),
	)
}

// QueryTokenRevokeSessions bulk-revokes every active refresh-token session
// for a user in one UPDATE, optionally excluding one session (exceptID).
func (q *SqliteQuerier) QueryTokenRevokeSessions(ctx context.Context, userID, exceptID string) bob.Query {
	mods := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))),
		um.Where(sqlite.Quote(models.ColumnTokenType).EQ(sqlite.Arg(models.TokenTypeRefresh))),
		um.Where(sqlite.Quote(models.ColumnRevoked).EQ(sqlite.Arg(false))),
	}
	if exceptID != "" {
		mods = append(mods, um.Where(sqlite.Quote("id").NE(sqlite.Arg(exceptID))))
	}
	return sqlite.Update(mods...)
}

func (q *SqliteQuerier) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableToken), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryWebauthnCredentialInsert(ctx context.Context, cred *models.WebauthnCredential) bob.Query {
	if cred.ID == "" {
		cred.ID = util.NewIDStripped()
	}
	if cred.CreatedAt.IsZero() {
		cred.CreatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
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
			sqlite.Arg(cred.ID),
			sqlite.Arg(cred.UserID),
			sqlite.Arg(cred.CredentialID),
			sqlite.Arg(cred.PublicKey),
			sqlite.Arg(cred.SignCount),
			sqlite.Arg(cred.Transports),
			sqlite.Arg(cred.AttestationType),
			sqlite.Arg(cred.Name),
			sqlite.Arg(cred.Data),
			sqlite.Arg(cred.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryWebauthnCredentialGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableWebauthnCredential), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryWebauthnCredentialGetByCredentialID(ctx context.Context, credentialID string) bob.Query {
	return sqlite.Select(sm.From(models.TableWebauthnCredential), sm.Where(sqlite.Quote(models.ColumnCredentialID).EQ(sqlite.Arg(credentialID))))
}

func (q *SqliteQuerier) QueryWebauthnCredentialListByUserID(ctx context.Context, userID string) bob.Query {
	return sqlite.Select(sm.From(models.TableWebauthnCredential), sm.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))))
}

func (q *SqliteQuerier) QueryWebauthnCredentialUpdate(ctx context.Context, cred *models.WebauthnCredential) bob.Query {
	return sqlite.Update(
		um.Table(models.TableWebauthnCredential),
		um.SetCol(models.ColumnSignCount).ToArg(cred.SignCount),
		um.SetCol(models.ColumnData).ToArg(cred.Data),
		um.SetCol(models.ColumnName).ToArg(cred.Name),
		um.SetCol(models.ColumnLastUsedAt).ToArg(cred.LastUsedAt),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(cred.ID))),
		um.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryWebauthnCredentialDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableWebauthnCredential), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryWebauthnChallengeInsert(ctx context.Context, ch *models.WebauthnChallenge) bob.Query {
	if ch.ID == "" {
		ch.ID = util.NewIDStripped()
	}
	if ch.CreatedAt.IsZero() {
		ch.CreatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
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
			sqlite.Arg(ch.ID),
			sqlite.Arg(ch.SessionKey),
			sqlite.Arg(ch.ChallengeType),
			sqlite.Arg(ch.UserID),
			sqlite.Arg(ch.Data),
			sqlite.Arg(ch.ExpiresAt),
			sqlite.Arg(ch.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryWebauthnChallengeGetBySessionKey(ctx context.Context, sessionKey string) bob.Query {
	return sqlite.Select(sm.From(models.TableWebauthnChallenge), sm.Where(sqlite.Quote(models.ColumnSessionKey).EQ(sqlite.Arg(sessionKey))))
}

func (q *SqliteQuerier) QueryWebauthnChallengeDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableWebauthnChallenge), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryAuditLogInsert(ctx context.Context, log *models.AuditLog) bob.Query {
	if log.ID == "" {
		log.ID = util.NewIDStripped()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
		im.Into(models.TableAuditLog,
			"id",
			models.ColumnUserID,
			models.ColumnEventType,
			models.ColumnMetadata,
			models.ColumnCreatedAt,
		),
		im.Values(
			sqlite.Arg(log.ID),
			sqlite.Arg(log.UserID),
			sqlite.Arg(log.EventType),
			sqlite.Arg(log.Metadata),
			sqlite.Arg(log.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryAuditLogListByUserID(ctx context.Context, userID string, filter models.AuditLogFilter, limit, offset int) bob.Query {
	mods := []bob.Mod[*dialect.SelectQuery]{
		sm.From(models.TableAuditLog),
		sm.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))),
		sm.OrderBy(sqlite.Quote(models.ColumnCreatedAt)).Desc(),
		sm.Limit(limit),
		sm.Offset(offset),
	}

	if filter.EventType != "" {
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnEventType).EQ(sqlite.Arg(filter.EventType))))
	}
	if filter.Since != nil {
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnCreatedAt).GTE(sqlite.Arg(*filter.Since))))
	}
	if filter.Until != nil {
		mods = append(mods, sm.Where(sqlite.Quote(models.ColumnCreatedAt).LTE(sqlite.Arg(*filter.Until))))
	}

	return sqlite.Select(mods...)
}

func (q *SqliteQuerier) QueryRoleInsert(ctx context.Context, role *models.Role) bob.Query {
	if role.ID == "" {
		role.ID = util.NewIDStripped()
	}
	if role.CreatedAt.IsZero() {
		role.CreatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
		im.Into(models.TableRole,
			"id",
			models.ColumnName,
			models.ColumnDescription,
			models.ColumnCreatedAt,
		),
		im.Values(
			sqlite.Arg(role.ID),
			sqlite.Arg(role.Name),
			sqlite.Arg(role.Description),
			sqlite.Arg(role.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryRoleGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableRole), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryRoleGetByName(ctx context.Context, name string) bob.Query {
	return sqlite.Select(sm.From(models.TableRole), sm.Where(sqlite.Quote(models.ColumnName).EQ(sqlite.Arg(name))))
}

func (q *SqliteQuerier) QueryRolesList(ctx context.Context) bob.Query {
	return sqlite.Select(sm.From(models.TableRole), sm.OrderBy(sqlite.Quote(models.ColumnName)))
}

func (q *SqliteQuerier) QueryRoleDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableRole), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryPermissionInsert(ctx context.Context, permission *models.Permission) bob.Query {
	if permission.ID == "" {
		permission.ID = util.NewIDStripped()
	}
	if permission.CreatedAt.IsZero() {
		permission.CreatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
		im.Into(models.TablePermission,
			"id",
			models.ColumnName,
			models.ColumnDescription,
			models.ColumnCreatedAt,
		),
		im.Values(
			sqlite.Arg(permission.ID),
			sqlite.Arg(permission.Name),
			sqlite.Arg(permission.Description),
			sqlite.Arg(permission.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryPermissionGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TablePermission), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryPermissionGetByName(ctx context.Context, name string) bob.Query {
	return sqlite.Select(sm.From(models.TablePermission), sm.Where(sqlite.Quote(models.ColumnName).EQ(sqlite.Arg(name))))
}

func (q *SqliteQuerier) QueryPermissionsList(ctx context.Context) bob.Query {
	return sqlite.Select(sm.From(models.TablePermission), sm.OrderBy(sqlite.Quote(models.ColumnName)))
}

func (q *SqliteQuerier) QueryPermissionDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TablePermission), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

// QueryUserRoleInsert is idempotent: granting a role the user already
// holds is a no-op (ON CONFLICT DO NOTHING on the composite PK) rather
// than a constraint-violation error.
func (q *SqliteQuerier) QueryUserRoleInsert(ctx context.Context, userID, roleID string) bob.Query {
	return sqlite.Insert(
		im.Into(models.TableUserRole, models.ColumnUserID, models.ColumnRoleID),
		im.Values(sqlite.Arg(userID), sqlite.Arg(roleID)),
		im.OnConflict(models.ColumnUserID, models.ColumnRoleID).DoNothing(),
	)
}

func (q *SqliteQuerier) QueryUserRoleDelete(ctx context.Context, userID, roleID string) bob.Query {
	return sqlite.Delete(
		dm.From(models.TableUserRole),
		dm.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))),
		dm.Where(sqlite.Quote(models.ColumnRoleID).EQ(sqlite.Arg(roleID))),
	)
}

func (q *SqliteQuerier) QueryRolesByUserID(ctx context.Context, userID string) bob.Query {
	return sqlite.Select(
		sm.Columns(
			sqlite.Quote(models.TableRole, "id"),
			sqlite.Quote(models.TableRole, models.ColumnName),
			sqlite.Quote(models.TableRole, models.ColumnDescription),
			sqlite.Quote(models.TableRole, models.ColumnCreatedAt),
		),
		sm.From(models.TableRole),
		sm.InnerJoin(models.TableUserRole).OnEQ(
			sqlite.Quote(models.TableUserRole, models.ColumnRoleID),
			sqlite.Quote(models.TableRole, "id"),
		),
		sm.Where(sqlite.Quote(models.TableUserRole, models.ColumnUserID).EQ(sqlite.Arg(userID))),
	)
}

// QueryRolePermissionInsert is idempotent: granting a permission the role
// already has is a no-op (ON CONFLICT DO NOTHING on the composite PK)
// rather than a constraint-violation error.
func (q *SqliteQuerier) QueryRolePermissionInsert(ctx context.Context, roleID, permissionID string) bob.Query {
	return sqlite.Insert(
		im.Into(models.TableRolePermission, models.ColumnRoleID, models.ColumnPermissionID),
		im.Values(sqlite.Arg(roleID), sqlite.Arg(permissionID)),
		im.OnConflict(models.ColumnRoleID, models.ColumnPermissionID).DoNothing(),
	)
}

func (q *SqliteQuerier) QueryRolePermissionDelete(ctx context.Context, roleID, permissionID string) bob.Query {
	return sqlite.Delete(
		dm.From(models.TableRolePermission),
		dm.Where(sqlite.Quote(models.ColumnRoleID).EQ(sqlite.Arg(roleID))),
		dm.Where(sqlite.Quote(models.ColumnPermissionID).EQ(sqlite.Arg(permissionID))),
	)
}

func (q *SqliteQuerier) QueryPermissionsByRoleID(ctx context.Context, roleID string) bob.Query {
	return sqlite.Select(
		sm.Columns(
			sqlite.Quote(models.TablePermission, "id"),
			sqlite.Quote(models.TablePermission, models.ColumnName),
			sqlite.Quote(models.TablePermission, models.ColumnDescription),
			sqlite.Quote(models.TablePermission, models.ColumnCreatedAt),
		),
		sm.From(models.TablePermission),
		sm.InnerJoin(models.TableRolePermission).OnEQ(
			sqlite.Quote(models.TableRolePermission, models.ColumnPermissionID),
			sqlite.Quote(models.TablePermission, "id"),
		),
		sm.Where(sqlite.Quote(models.TableRolePermission, models.ColumnRoleID).EQ(sqlite.Arg(roleID))),
	)
}

// QueryPermissionsByUserID resolves the permissions a user holds transitively
// through every role granted to them: ezauth_user_roles -> ezauth_role_permissions
// -> ezauth_permissions. DISTINCT guards against double-counting a permission
// granted via more than one of the user's roles.
func (q *SqliteQuerier) QueryPermissionsByUserID(ctx context.Context, userID string) bob.Query {
	return sqlite.Select(
		sm.Distinct(),
		sm.Columns(
			sqlite.Quote(models.TablePermission, "id"),
			sqlite.Quote(models.TablePermission, models.ColumnName),
			sqlite.Quote(models.TablePermission, models.ColumnDescription),
			sqlite.Quote(models.TablePermission, models.ColumnCreatedAt),
		),
		sm.From(models.TablePermission),
		sm.InnerJoin(models.TableRolePermission).OnEQ(
			sqlite.Quote(models.TableRolePermission, models.ColumnPermissionID),
			sqlite.Quote(models.TablePermission, "id"),
		),
		sm.InnerJoin(models.TableUserRole).OnEQ(
			sqlite.Quote(models.TableUserRole, models.ColumnRoleID),
			sqlite.Quote(models.TableRolePermission, models.ColumnRoleID),
		),
		sm.Where(sqlite.Quote(models.TableUserRole, models.ColumnUserID).EQ(sqlite.Arg(userID))),
	)
}

func (q *SqliteQuerier) QueryOrganizationInsert(ctx context.Context, org *models.Organization) bob.Query {
	if org.ID == "" {
		org.ID = util.NewIDStripped()
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now().UTC()
	}
	return sqlite.Insert(
		im.Into(models.TableOrganization,
			"id",
			models.ColumnName,
			models.ColumnCreatedAt,
		),
		im.Values(
			sqlite.Arg(org.ID),
			sqlite.Arg(org.Name),
			sqlite.Arg(org.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryOrganizationGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableOrganization), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryOrganizationsList(ctx context.Context, limit, offset int) bob.Query {
	return sqlite.Select(
		sm.From(models.TableOrganization),
		sm.OrderBy(sqlite.Quote(models.ColumnName)),
		sm.Limit(limit),
		sm.Offset(offset),
	)
}

func (q *SqliteQuerier) QueryOrganizationDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableOrganization), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

// QueryOrgMemberUpsert inserts a (org, user) membership, or updates its
// role_id if the pair already exists (composite PK on org_id, user_id).
func (q *SqliteQuerier) QueryOrgMemberUpsert(ctx context.Context, orgID, userID, roleID string) bob.Query {
	return sqlite.Insert(
		im.Into(models.TableOrgMember, models.ColumnOrgID, models.ColumnUserID, models.ColumnRoleID),
		im.Values(sqlite.Arg(orgID), sqlite.Arg(userID), sqlite.Arg(roleID)),
		im.OnConflict(models.ColumnOrgID, models.ColumnUserID).DoUpdate(
			im.SetExcluded(models.ColumnRoleID),
		),
	)
}

func (q *SqliteQuerier) QueryOrgMemberRemove(ctx context.Context, orgID, userID string) bob.Query {
	return sqlite.Delete(
		dm.From(models.TableOrgMember),
		dm.Where(sqlite.Quote(models.ColumnOrgID).EQ(sqlite.Arg(orgID))),
		dm.Where(sqlite.Quote(models.ColumnUserID).EQ(sqlite.Arg(userID))),
	)
}

// QueryOrgMembersByOrgID lists an org's members, joined with ezauth_roles for the role name.
func (q *SqliteQuerier) QueryOrgMembersByOrgID(ctx context.Context, orgID string) bob.Query {
	return sqlite.Select(
		sm.Columns(
			sqlite.Quote(models.TableOrgMember, models.ColumnOrgID),
			sqlite.Quote(models.TableOrgMember, models.ColumnUserID),
			sqlite.Quote(models.TableOrgMember, models.ColumnRoleID),
			sqlite.Quote(models.TableRole, models.ColumnName).As(models.ColumnRoleName),
			sqlite.Quote(models.TableOrgMember, models.ColumnCreatedAt),
		),
		sm.From(models.TableOrgMember),
		sm.InnerJoin(models.TableRole).OnEQ(
			sqlite.Quote(models.TableRole, "id"),
			sqlite.Quote(models.TableOrgMember, models.ColumnRoleID),
		),
		sm.Where(sqlite.Quote(models.TableOrgMember, models.ColumnOrgID).EQ(sqlite.Arg(orgID))),
	)
}

// QueryOrganizationsByUserID lists the organizations a user belongs to.
func (q *SqliteQuerier) QueryOrganizationsByUserID(ctx context.Context, userID string) bob.Query {
	return sqlite.Select(
		sm.Columns(
			sqlite.Quote(models.TableOrganization, "id"),
			sqlite.Quote(models.TableOrganization, models.ColumnName),
			sqlite.Quote(models.TableOrganization, models.ColumnCreatedAt),
		),
		sm.From(models.TableOrganization),
		sm.InnerJoin(models.TableOrgMember).OnEQ(
			sqlite.Quote(models.TableOrgMember, models.ColumnOrgID),
			sqlite.Quote(models.TableOrganization, "id"),
		),
		sm.Where(sqlite.Quote(models.TableOrgMember, models.ColumnUserID).EQ(sqlite.Arg(userID))),
	)
}
