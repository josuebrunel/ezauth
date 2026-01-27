package postgres

import (
	"context"

	"github.com/josuebrunel/ezauth/pkg/db/models"
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
	return psql.Insert(
		im.Into(psql.Quote(models.TableUser),
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
			psql.Arg(user.Email),
			psql.Arg(user.PasswordHash),
			psql.Arg(user.Provider),
			psql.Arg(user.ProviderID),
			psql.Arg(user.EmailVerified),
			psql.Arg(user.AppMetadata),
			psql.Arg(user.UserMetadata),
			psql.Arg(user.FirstName),
			psql.Arg(user.LastName),
			psql.Arg(user.LastActiveAt),
			psql.Arg(user.Locale),
			psql.Arg(user.Timezone),
			psql.Arg(user.EmailVerifiedAt),
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
		um.Where(psql.Quote("id").EQ(psql.Arg(user.ID))),
	}

	if user.Email != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnEmail).EQ(psql.Arg(user.Email))))
	}

	if user.PasswordHash != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnPasswordHash).EQ(psql.Arg(user.PasswordHash))))
	}

	if user.Provider != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnProvider).EQ(psql.Arg(user.Provider))))
	}

	if user.ProviderID != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnProviderID).EQ(psql.Arg(user.ProviderID))))
	}

	qm = append(qm, um.Set(psql.Quote(models.ColumnEmailVerified).EQ(psql.Arg(user.EmailVerified))))

	if user.AppMetadata != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnAppMetadata).EQ(psql.Arg(user.AppMetadata))))
	}

	if user.UserMetadata != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnUserMetadata).EQ(psql.Arg(user.UserMetadata))))
	}

	if user.FirstName != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnFirstName).EQ(psql.Arg(user.FirstName))))
	}

	if user.LastName != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnLastName).EQ(psql.Arg(user.LastName))))
	}

	if user.LastActiveAt != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnLastActiveAt).EQ(psql.Arg(user.LastActiveAt))))
	}

	if user.Locale != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnLocale).EQ(psql.Arg(user.Locale))))
	}

	if user.Timezone != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnTimezone).EQ(psql.Arg(user.Timezone))))
	}

	if user.EmailVerifiedAt != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnEmailVerifiedAt).EQ(psql.Arg(user.EmailVerifiedAt))))
	}

	if user.Roles != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnRoles).EQ(psql.Arg(user.Roles))))
	}

	if user.UpdatedAt.IsZero() {
		qm = append(qm, um.Set(psql.Quote(models.ColumnUpdatedAt).EQ(psql.Arg(user.UpdatedAt))))
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
	return psql.Insert(
		im.Into(psql.Quote(models.TableToken),
			models.ColumnUserID,
			models.ColumnToken,
			models.ColumnTokenType,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
			models.ColumnRevoked,
			models.ColumnMetadata,
		),
		im.Values(
			psql.Arg(token.UserID),
			psql.Arg(token.Token),
			psql.Arg(token.TokenType),
			psql.Arg(token.ExpiresAt),
			psql.Arg(token.CreatedAt),
			psql.Arg(token.Revoked),
			psql.Arg(token.Metadata),
		),
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
		um.SetCol(psql.Quote(models.ColumnRevoked).String()).To(true),
		um.Where(psql.Quote("id").EQ(psql.Arg(id))),
	)
}

func (q *PSQLQuerier) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(psql.Quote(models.TableToken)), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQuerier) QueryPasswordlessTokenInsert(ctx context.Context, token *models.PasswordlessToken) bob.Query {
	return psql.Insert(
		im.Into(psql.Quote(models.TablePasswordlessToken),
			models.ColumnEmail,
			models.ColumnToken,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
		),
		im.Values(
			psql.Arg(token.Email),
			psql.Arg(token.Token),
			psql.Arg(token.ExpiresAt),
			psql.Arg(token.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQuerier) QueryPasswordlessTokenGetByToken(ctx context.Context, token string) bob.Query {
	return psql.Select(
		sm.From(psql.Quote(models.TablePasswordlessToken)),
		sm.Where(psql.Quote(models.ColumnToken).EQ(psql.Arg(token))),
	)
}

func (q *PSQLQuerier) QueryPasswordlessTokenDelete(ctx context.Context, token string) bob.Query {
	return psql.Delete(
		dm.From(psql.Quote(models.TablePasswordlessToken)),
		dm.Where(psql.Quote(models.ColumnToken).EQ(psql.Arg(token))),
	)
}
