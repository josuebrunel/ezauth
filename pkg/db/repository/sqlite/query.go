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

type SqliteQuerier struct {
}

func (q *SqliteQuerier) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
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
			sqlite.Arg(user.Email),
			sqlite.Arg(user.PasswordHash),
			sqlite.Arg(user.Provider),
			sqlite.Arg(user.ProviderID),
			sqlite.Arg(user.EmailVerified),
			sqlite.Arg(user.AppMetadata),
			sqlite.Arg(user.UserMetadata),
			sqlite.Arg(user.CreatedAt),
			sqlite.Arg(user.UpdatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return sqlite.Select(sm.From(models.TableUser), sm.Where(sqlite.Quote(models.ColumnEmail).EQ(sqlite.Arg(email))))
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

func (q *SqliteQuerier) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableUser), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
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

func (q *SqliteQuerier) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(models.TableToken), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return sqlite.Select(sm.From(models.TableToken), sm.Where(sqlite.Quote(models.ColumnToken).EQ(sqlite.Arg(token))))
}

func (q *SqliteQuerier) QueryTokenRevoke(ctx context.Context, id string) bob.Query {
	return sqlite.Update(
		um.Table(models.TableToken),
		um.SetCol(models.ColumnRevoked).ToArg(true),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))),
	)
}

func (q *SqliteQuerier) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(models.TableToken), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQuerier) QueryPasswordlessTokenInsert(ctx context.Context, token *models.PasswordlessToken) bob.Query {
	return sqlite.Insert(
		im.Into(models.TablePasswordlessToken,
			models.ColumnEmail,
			models.ColumnToken,
			models.ColumnExpiresAt,
			models.ColumnCreatedAt,
		),
		im.Values(
			sqlite.Arg(token.Email),
			sqlite.Arg(token.Token),
			sqlite.Arg(token.ExpiresAt),
			sqlite.Arg(token.CreatedAt),
		),
		im.Returning("*"),
	)
}

func (q *SqliteQuerier) QueryPasswordlessTokenGetByToken(ctx context.Context, token string) bob.Query {
	return sqlite.Select(
		sm.From(models.TablePasswordlessToken),
		sm.Where(sqlite.Quote(models.ColumnToken).EQ(sqlite.Arg(token))),
	)
}

func (q *SqliteQuerier) QueryPasswordlessTokenDelete(ctx context.Context, token string) bob.Query {
	return sqlite.Delete(
		dm.From(models.TablePasswordlessToken),
		dm.Where(sqlite.Quote(models.ColumnToken).EQ(sqlite.Arg(token))),
	)
}
