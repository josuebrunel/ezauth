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
			models.ColumnPasswordHash,
			models.ColumnProvider,
			models.ColumnProviderID,
			models.ColumnEmailVerified,
			models.ColumnAppMetadata,
			models.ColumnUserMetadata,
			models.ColumnFirstName,
			models.ColumnLastName,
			models.ColumnLastActiveAt,
			models.ColumnLocale,
			models.ColumnTimezone,
			models.ColumnEmailVerifiedAt,
			models.ColumnRoles,
			models.ColumnCreatedAt,
			models.ColumnUpdatedAt,
		),
		im.Values(
			mysql.Arg(user.ID),
			mysql.Arg(user.Email),
			mysql.Arg(user.PasswordHash),
			mysql.Arg(user.Provider),
			mysql.Arg(user.ProviderID),
			mysql.Arg(user.EmailVerified),
			mysql.Arg(user.AppMetadata),
			mysql.Arg(user.UserMetadata),
			mysql.Arg(user.FirstName),
			mysql.Arg(user.LastName),
			mysql.Arg(user.LastActiveAt),
			mysql.Arg(user.Locale),
			mysql.Arg(user.Timezone),
			mysql.Arg(user.EmailVerifiedAt),
			mysql.Arg(user.Roles),
			mysql.Arg(user.CreatedAt),
			mysql.Arg(user.UpdatedAt),
		),
	)
}

func (q *MysqlQuerier) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return mysql.Select(sm.From(models.TableUser), sm.Where(mysql.Quote(models.ColumnEmail).EQ(mysql.Arg(email))))
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

	if user.Roles != "" {
		qm = append(qm, um.SetCol(models.ColumnRoles).ToArg(user.Roles))
	}

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

func (q *MysqlQuerier) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return mysql.Delete(dm.From(models.TableToken), dm.Where(mysql.Quote("id").EQ(mysql.Arg(id))))
}
