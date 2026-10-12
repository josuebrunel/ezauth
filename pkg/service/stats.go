package service

import (
	"context"
	"fmt"
	"time"

	"github.com/josuebrunel/ezauth/pkg/db/models"
)

// UserStats counts users for a dashboard: the total, those who joined or were
// last active at or after since, and those who can't sign in (suspended or
// locked out). ezauth performs no authorization check here, same as UsersList;
// the caller must verify the requester may see these numbers.
func (a *Auth) UserStats(ctx context.Context, since time.Time) (*models.UserStats, error) {
	return a.Repo.UserStats(ctx, since.UTC())
}

// DayCount is how many users joined on one UTC day.
type DayCount struct {
	Day   time.Time // UTC midnight
	Count int
}

// UserSignups counts the users who joined at or after since, per UTC day,
// oldest first. Days with no sign-ups are left out, so a caller drawing a
// chart fills the gaps. ezauth performs no authorization check here.
func (a *Auth) UserSignups(ctx context.Context, since time.Time) ([]DayCount, error) {
	rows, err := a.Repo.UserSignupsByDay(ctx, since.UTC())
	if err != nil {
		return nil, err
	}
	out := make([]DayCount, 0, len(rows))
	for _, r := range rows {
		day, err := time.Parse("2006-01-02", r.Day)
		if err != nil {
			return nil, fmt.Errorf("unexpected day %q from the database: %w", r.Day, err)
		}
		out = append(out, DayCount{Day: day, Count: r.Count})
	}
	return out, nil
}
