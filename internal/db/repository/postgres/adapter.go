package postgres

import (
	"context"

	"github.com/josuebrunel/ezauth/internal/db/models"
	"github.com/stephenafamo/bob"
	"github.com/stephenafamo/bob/dialect/psql"
	"github.com/stephenafamo/bob/dialect/psql/dialect"
	"github.com/stephenafamo/bob/dialect/psql/dm"
	"github.com/stephenafamo/bob/dialect/psql/im"
	"github.com/stephenafamo/bob/dialect/psql/sm"
	"github.com/stephenafamo/bob/dialect/psql/um"
)

const (
	TableUser           = "users"
	TableToken          = "tokens"
	ColumnEmail         = "email"
	ColumnPasswordHash  = "password_hash"
	ColumnProvider      = "provider"
	ColumnProviderID    = "provider_id"
	ColumnEmailVerified = "email_verified"
	ColumnAppMetadata   = "app_metadata"
	ColumnUserMetadata  = "user_metadata"
	ColumnCreatedAt     = "created_at"
	ColumnUpdatedAt     = "updated_at"
)

type PSQLQueryAdapter struct {
}

func (q *PSQLQueryAdapter) QueryUserInsert(ctx context.Context, user *models.User) bob.Query {
	return psql.Insert(
		im.Into(psql.Quote(TableUser),
			ColumnEmail,
			ColumnPasswordHash,
			ColumnProvider,
			ColumnProviderID,
			ColumnEmailVerified,
			ColumnAppMetadata,
			ColumnUserMetadata,
			ColumnCreatedAt,
			ColumnUpdatedAt,
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
	return psql.Select(sm.From(TableUser), sm.Where(psql.Quote("email").EQ(psql.Arg(email))))
}

func (q *PSQLQueryAdapter) QueryUserGetByID(ctx context.Context, id string) bob.Query {
	return psql.Select(sm.From(TableUser), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQueryAdapter) QueryUserUpdate(ctx context.Context, user *models.User) bob.Query {
	qm := []bob.Mod[*dialect.UpdateQuery]{
		um.Table(TableUser),
		um.Where(psql.Quote("id").EQ(psql.Arg(user.ID))),
	}

	if user.Provider != "" {
		qm = append(qm, um.Set(psql.Quote("provider").EQ(psql.Arg(user.Provider))))
	}

	if user.ProviderID != nil {
		qm = append(qm, um.Set(psql.Quote("provider_id").EQ(psql.Arg(user.ProviderID))))
	}

	if user.AppMetadata != nil {
		qm = append(qm, um.Set(psql.Quote("app_metadata").EQ(psql.Arg(user.AppMetadata))))
	}

	if user.UserMetadata != nil {
		qm = append(qm, um.Set(psql.Quote("user_metadata").EQ(psql.Arg(user.UserMetadata))))
	}

	if user.UpdatedAt.IsZero() {
		qm = append(qm, um.Set(psql.Quote("updated_at").EQ(psql.Arg(user.UpdatedAt))))
	}

	return psql.Update(qm...)
}

func (q *PSQLQueryAdapter) QueryUserDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(TableUser), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQueryAdapter) QueryTokenInsert(ctx context.Context, token *models.Token) bob.Query {
	return psql.Insert(
		im.Into(TableToken),
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
	return psql.Select(sm.From(TableToken), sm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}

func (q *PSQLQueryAdapter) QueryTokenGetByToken(ctx context.Context, token string) bob.Query {
	return psql.Select(sm.From(TableToken), sm.Where(psql.Quote("token").EQ(psql.Arg(token))))
}

func (q *PSQLQueryAdapter) QueryTokenDelete(ctx context.Context, id string) bob.Query {
	return psql.Delete(dm.From(TableToken), dm.Where(psql.Quote("id").EQ(psql.Arg(id))))
}
