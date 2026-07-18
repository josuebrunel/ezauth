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
			psql.Arg(user.IsActive),
			psql.Arg(user.AvatarURL),
			psql.Arg(user.Nickname),
			psql.Arg(user.Roles),
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

	qm = append(qm, um.Returning("*"))

	return psql.Update(qm...)
}

func (q *PSQLQuerier) QueryUserCheckPasswordHash(ctx context.Context, email, passwordHash string) bob.Query {
	return psql.Select(sm.From(psql.Quote(models.TableUser)), sm.Where(psql.Quote(models.ColumnEmail).EQ(psql.Arg(email)).And(psql.Quote(models.ColumnPasswordHash).EQ(psql.Arg(passwordHash)))))
}

func (q *PSQLQuerier) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableUser)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
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

func (q *PSQLQuerier) QueryTokenRevoke(ctx context.Context, id string) bob.Query {
	return psql.Update(
		um.Table(psql.Quote(models.TableToken)),
		um.SetCol(models.ColumnRevoked).To(true),
		um.Where(psql.Quote("id").EQ(psql.Arg(id))),
	)
}

func (q *PSQLQuerier) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableToken)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}
