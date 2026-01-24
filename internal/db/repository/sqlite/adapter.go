package sqlite

import (
	"context"

	"github.com/josuebrunel/ezauth/internal/db/models"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/sqlite"
	"github.com/stephenafamo/bob/dialect/sqlite/dialect"
	"github.com/stephenafamo/bob/dialect/sqlite/dm"
	"github.com/stephenafamo/bob/dialect/sqlite/im"
	"github.com/stephenafamo/bob/dialect/sqlite/sm"
	"github.com/stephenafamo/bob/dialect/sqlite/um"
)

// implement the SQLiteQueryAdapter
const (
	TableUser  = "users"
	TableToken = "tokens"
)

type SqliteQueryAdapter struct {
}

func (q *SqliteQueryAdapter) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
	return sqlite.Insert(
		im.Into(TableUser),
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
	)
}

func (q *SqliteQueryAdapter) QueryUserGetByEmail(ctx context.Context, email string) bob.Query {
	return sqlite.Select(sm.From(TableUser), sm.Where(sqlite.Quote("email").EQ(sqlite.Arg(email))))
}

func (q *SqliteQueryAdapter) QueryUserGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(TableUser), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQueryAdapter) QueryUserUpdate(ctx context.Context, user *models.User) bob.Query {
	qm := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(TableUser),
		um.Where(sqlite.Quote("id").EQ(sqlite.Arg(user.ID))),
	}

	if user.Provider != "" {
		qm = append(qm, um.Set(sqlite.Quote("provider").EQ(sqlite.Arg(user.Provider))))
	}

	if user.ProviderID != nil {
		qm = append(qm, um.Set(sqlite.Quote("provider_id").EQ(sqlite.Arg(user.ProviderID))))
	}

	if user.AppMetadata != nil {
		qm = append(qm, um.Set(sqlite.Quote("app_metadata").EQ(sqlite.Arg(user.AppMetadata))))
	}

	if user.UserMetadata != nil {
		qm = append(qm, um.Set(sqlite.Quote("user_metadata").EQ(sqlite.Arg(user.UserMetadata))))
	}

	if user.UpdatedAt.IsZero() {
		qm = append(qm, um.Set(sqlite.Quote("updated_at").EQ(sqlite.Arg(user.UpdatedAt))))
	}

	return sqlite.Update(qm...)
}

func (q *SqliteQueryAdapter) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(TableUser), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQueryAdapter) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
	return sqlite.Insert(
		im.Into(TableToken),
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
	)
}

func (q *SqliteQueryAdapter) QueryTokenGetByID(ctx context.Context, id string) bob.Query {
	return sqlite.Select(sm.From(TableToken), sm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}

func (q *SqliteQueryAdapter) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return sqlite.Select(sm.From(TableToken), sm.Where(sqlite.Quote("token").EQ(sqlite.Arg(token))))
}

func (q *SqliteQueryAdapter) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return sqlite.Delete(dm.From(TableToken), dm.Where(sqlite.Quote("id").EQ(sqlite.Arg(id))))
}
