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

type PSQLQueryAdapter struct {
}

func (q *PSQLQueryAdapter) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
	return psql.Insert(
		im.Into(psql.Quote(models.TableUser),
			models.ColumnEmail,
			models.ColumnPasswordHash,
			models.ColumnProvider,
			models.ColumnProviderID,
			models.ColumnEmailVerified,
			models.ColumnAppMetadata,
			models.ColumnUserMetadata,
			models.ColumnCreatedAt,
			models.ColumnUpdatedAt,
		),
		im.Values(
			psql.Arg(
				user.Email,
				user.PasswordHash,
				user.Provider,
				user.ProviderID,
				user.EmailVerified,
				user.AppMetadata,
				user.UserMetadata,
				user.CreatedAt,
				user.UpdatedAt,
			),
		),
		im.Returning("*"),
	)
}

func (q *PSQLQueryAdapter) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return psql.Select(sm.From(models.TableUser), sm.Where(psql.Quote(models.ColumnEmail).EQ(psql.Arg(email))))
}

func (q *PSQLQueryAdapter) QueryUserGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(models.TableUser), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQueryAdapter) QueryUserUpdate(ctx context.Context, user *models.User) bob.Query {
	qm := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(models.TableUser),
		um.Where(psql.Quote("id").EQ(psql.Arg(user.ID))),
	}

	if user.Provider != "" {
		qm = append(qm, um.Set(psql.Quote(models.ColumnProvider).EQ(psql.Arg(user.Provider))))
	}

	if user.ProviderID != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnProviderID).EQ(psql.Arg(user.ProviderID))))
	}

	if user.AppMetadata != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnAppMetadata).EQ(psql.Arg(user.AppMetadata))))
	}

	if user.UserMetadata != nil {
		qm = append(qm, um.Set(psql.Quote(models.ColumnUserMetadata).EQ(psql.Arg(user.UserMetadata))))
	}

	if user.UpdatedAt.IsZero() {
		qm = append(qm, um.Set(psql.Quote(models.ColumnUpdatedAt).EQ(psql.Arg(user.UpdatedAt))))
	}

	return psql.Update(qm...)
}

func (q *PSQLQueryAdapter) QueryUserCheckPasswordHash(ctx context.Context, email, passwordHash string) bob.Query {
	return psql.Select(sm.From(models.TableUser), sm.Where(psql.Quote(models.ColumnEmail).EQ(psql.Arg(email)).And(psql.Quote(models.ColumnPasswordHash).EQ(psql.Arg(passwordHash)))))
}

func (q *PSQLQueryAdapter) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(models.TableUser), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQueryAdapter) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
	return psql.Insert(
		im.Into(models.TableToken,
			models.ColumnUserID,
			models.ColumnToken,
			models.ColumnTokenType,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
			models.ColumnRevoked,
			models.ColumnMetadata,
		),
		im.Values(
			psql.Arg(
				token.UserID,
				token.Token,
				token.TokenType,
				token.ExpiresAt,
				token.CreatedAt,
				token.Revoked,
				token.Metadata,
			),
		),
	)
}

func (q *PSQLQueryAdapter) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(models.TableToken), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQueryAdapter) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return psql.Select(sm.From(models.TableToken), sm.Where(psql.Quote(models.ColumnToken).EQ(psql.Arg(token))))
}

func (q *PSQLQueryAdapter) QueryTokenRevoke(ctx context.Context, id string) bob.Query {
	return psql.Update(
		um.Table(models.TableToken),
		um.SetCol(psql.Quote(models.ColumnRevoked).String()).To(true),
		um.Where(psql.Quote("id").EQ(psql.Arg(id))),
	)
}

func (q *PSQLQueryAdapter) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(models.TableToken), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}
