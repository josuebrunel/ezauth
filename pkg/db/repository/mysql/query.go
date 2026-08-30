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
			mysql.Arg(user.IsActive),
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

func (q *MysqlQuerier) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableUser), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
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

func (q *MysqlQuerier) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return mysql.Select(sm.From(models.TableToken), sm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}

func (q *MysqlQuerier) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return mysql.Select(sm.From(models.TableToken), sm.Where(mysql.Quote(models.ColumnToken).EQ(mysql.Arg(token))))
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
