package sqlite

import (
	"context"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/sqlite"
	"github.com/stephenafamo/bob/dialect/sqlite/dialect"
	"github.com/stephenafamo/bob/dialect/sqlite/dm"
	"github.com/stephenafamo/bob/dialect/sqlite/im"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
	"github.com/stephenafamo/bob/dialect/sqlite/um"
)

type SqliteQueryAdapter struct {
}

func (q *SqliteQueryAdapter) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
	return sqlite.Insert(
		im.Into(models.TableUser,
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
			sqlite.Arg(
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

func (q *SqliteQueryAdapter) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return sqlite.Select(sm.From(models.TableUser), sm.Where(sqlite.Quote(models.ColumnEmail).EQ(sqlite.Arg(email))))
}

func (q *SqliteQueryAdapter) QueryUserGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableUser), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQueryAdapter) QueryUserGetByProvider(ctx context.Context, provider, providerID string) bob.Query {
	return sqlite.Select(
		sm.From(models.TableUser),
		sm.Where(
			sqlite.Quote(models.ColumnProvider).EQ(sqlite.Arg(provider)).
				And(sqlite.Quote(models.ColumnProviderID).EQ(sqlite.Arg(providerID))),
		),
	)
}

func (q *SqliteQueryAdapter) QueryUserUpdate(ctx context.Context, user *models.User) bob.Query {
	qm := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(models.TableUser),
		um.SetCol(models.ColumnUpdatedAt).ToArg(time.Now().UTC()),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(user.ID))),
		um.Returning("*"),
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

	return sqlite.Update(qm...)
}

func (q *SqliteQueryAdapter) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableUser), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQueryAdapter) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
	return sqlite.Insert(
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
			sqlite.Arg(
				token.UserID,
				token.Token,
				token.TokenType,
				token.ExpiresAt,
				token.CreatedAt,
				token.Revoked,
				token.Metadata,
			),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQueryAdapter) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableToken), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQueryAdapter) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return sqlite.Select(sm.From(models.TableToken), sm.Where(sqlite.Quote(models.ColumnToken).EQ(sqlite.Arg(token))))
}

func (q *SqliteQueryAdapter) QueryTokenRevoke(ctx context.Context, id string) bob.Query {
	return sqlite.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))),
	)
}

func (q *SqliteQueryAdapter) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableToken), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}
