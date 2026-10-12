package service

import (
	"context"
	"testing"
	"time"
)

// A persistent test database already holds other tests' users, so these tests
// compare numbers before and after rather than expecting absolute values.
func TestUserStats(t *testing.T) {
	ctx := context.Background()
	auth := setupTestDB(t)
	since := time.Now().UTC().Add(-time.Minute)

	before, err := auth.UserStats(ctx, since)
	if err != nil {
		t.Fatalf("UserStats failed: %v", err)
	}

	a, b, c := profileTestUser(t, auth), profileTestUser(t, auth), profileTestUser(t, auth)
	_ = a
	// b was last active just now; c is suspended.
	now := time.Now().UTC()
	b.LastActiveAt = &now
	if _, err := auth.UserUpdate(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.UserSuspend(ctx, c.ID); err != nil {
		t.Fatal(err)
	}

	after, err := auth.UserStats(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	for name, delta := range map[string][2]int{
		"total":         {after.Total - before.Total, 3},
		"created since": {after.CreatedSince - before.CreatedSince, 3},
		"active since":  {after.ActiveSince - before.ActiveSince, 1},
		"inactive":      {after.Inactive - before.Inactive, 1},
	} {
		if delta[0] != delta[1] {
			t.Errorf("%s grew by %d, want %d (before %+v, after %+v)", name, delta[0], delta[1], before, after)
		}
	}

	t.Run("a cutoff in the future counts nobody as new or active", func(t *testing.T) {
		got, err := auth.UserStats(ctx, time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if got.CreatedSince != 0 || got.ActiveSince != 0 {
			t.Errorf("expected no new or active users after a future cutoff, got %+v", got)
		}
		if got.Total < 3 {
			t.Errorf("total should not depend on the cutoff, got %d", got.Total)
		}
	})
}

func TestUserSignups(t *testing.T) {
	ctx := context.Background()
	auth := setupTestDB(t)

	// Back-date users to two quiet days so other tests' users (all created
	// today) can't land on them.
	day1 := time.Date(2020, 3, 14, 23, 30, 0, 0, time.UTC)
	day2 := time.Date(2020, 3, 15, 0, 15, 0, 0, time.UTC)
	for _, at := range []time.Time{day1, day1.Add(-time.Hour), day2} {
		u := profileTestUser(t, auth)
		query := "UPDATE ezauth_users SET created_at = ? WHERE id = ?"
		if auth.Repo.Opts.Dialect == "postgres" {
			query = "UPDATE ezauth_users SET created_at = $1 WHERE id = $2"
		}
		if _, err := auth.Repo.DB().ExecContext(ctx, query, at, u.ID); err != nil {
			t.Fatalf("back-dating failed: %v", err)
		}
	}

	got, err := auth.UserSignups(ctx, time.Date(2020, 3, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("UserSignups failed: %v", err)
	}
	counts := map[string]int{}
	var last time.Time
	for _, d := range got {
		if !d.Day.After(last) {
			t.Errorf("days are not strictly oldest first: %s after %s", d.Day, last)
		}
		last = d.Day
		counts[d.Day.Format("2006-01-02")] = d.Count
		if d.Day != d.Day.UTC().Truncate(24*time.Hour) {
			t.Errorf("day %s is not UTC midnight", d.Day)
		}
	}
	if counts["2020-03-14"] != 2 || counts["2020-03-15"] != 1 {
		t.Errorf("counts for the back-dated days = %v, want 2020-03-14:2 and 2020-03-15:1", counts)
	}
	if _, ok := counts["2020-03-13"]; ok {
		t.Error("a day with no sign-ups should be omitted")
	}

	t.Run("nothing before the cutoff", func(t *testing.T) {
		got, err := auth.UserSignups(ctx, time.Date(2020, 3, 15, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range got {
			if d.Day.Format("2006-01-02") == "2020-03-14" {
				t.Error("the cutoff did not exclude the earlier day")
			}
		}
	})
}

// Times must be written in UTC. On SQLite a time.Time is stored as text with
// its zone, so a local-time value compares wrongly with a UTC cutoff: with the
// server in UTC+5, a user active "now" looked like they were active in the
// future. Postgres and MySQL store real timestamps and never showed it. See
// #220.
func TestLastActiveAtIsStoredInUTC(t *testing.T) {
	ctx := context.Background()
	auth := setupTestDB(t)

	prev := time.Local
	time.Local = time.FixedZone("TEST+5", 5*60*60)
	defer func() { time.Local = prev }()

	future := time.Now().UTC().Add(time.Hour)
	before, err := auth.UserStats(ctx, future)
	if err != nil {
		t.Fatal(err)
	}

	user := profileTestUser(t, auth)
	if _, err := auth.TokenCreate(ctx, user); err != nil { // writes last_active_at
		t.Fatalf("TokenCreate failed: %v", err)
	}

	after, err := auth.UserStats(ctx, future)
	if err != nil {
		t.Fatal(err)
	}
	if after.ActiveSince != before.ActiveSince {
		t.Errorf("a user who was just active counted as active after a cutoff an hour in the future: %d -> %d (written in local time?)",
			before.ActiveSince, after.ActiveSince)
	}

	// And it still counts as active since a cutoff in the recent past.
	recent, err := auth.UserStats(ctx, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if recent.ActiveSince < 1 {
		t.Errorf("expected the just-active user to count since a minute ago, got %+v", recent)
	}
}
