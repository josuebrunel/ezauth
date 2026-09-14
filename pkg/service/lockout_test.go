package service

import (
	"context"
	"testing"
	"time"

	"github.com/josuebrunel/ezauth/pkg/config"
	"github.com/josuebrunel/ezauth/pkg/util"
)

func setupLockoutTestDB(t *testing.T, maxAttempts int, lockoutDuration time.Duration) *Auth {
	dialect, dsn := util.GetTestDBConfig("lockout_test")

	cfg := &config.Config{
		DB: config.Database{
			Dialect: dialect,
			DSN:     dsn,
		},
		JWTSecret: "test-secret-0123456789-0123456789",
		Hashing:   config.Hashing{BcryptCost: 4}, // bcrypt.MinCost: correctness doesn't need real cost-14 hashing
		AccountLockout: config.AccountLockout{
			Enabled:         true,
			MaxAttempts:     maxAttempts,
			LockoutDuration: lockoutDuration,
		},
	}
	auth, err := NewFromConfig(cfg, "auth")
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	if err := ensureMigrated(auth.Repo.DB(), dialect, dsn); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}
	return auth
}

func TestAccountLockout(t *testing.T) {
	auth := setupLockoutTestDB(t, 3, time.Hour)
	ctx := context.Background()

	email := util.UniqueEmail("lockout")
	password := "correct-horse-battery"
	if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	wrongLogin := func() error {
		_, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong-password"})
		return err
	}

	t.Run("failed attempts below threshold stay unlocked", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			if err := wrongLogin(); err == nil {
				t.Fatal("expected error for wrong password")
			}
		}
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if !user.IsActive || user.FailedLoginAttempts != 2 {
			t.Fatalf("expected active user with 2 failed attempts, got IsActive=%v attempts=%d", user.IsActive, user.FailedLoginAttempts)
		}
	})

	t.Run("threshold locks the account", func(t *testing.T) {
		if err := wrongLogin(); err == nil {
			t.Fatal("expected error for wrong password")
		}

		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.IsActive || user.LockedUntil == nil {
			t.Fatalf("expected locked user, got IsActive=%v lockedUntil=%v", user.IsActive, user.LockedUntil)
		}

		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != ErrAccountLocked {
			t.Fatalf("expected ErrAccountLocked even with correct password, got %v", err)
		}
	})

	t.Run("account auto-unlocks once the window passes", func(t *testing.T) {
		// Force the lockout into the past to simulate the window elapsing.
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		past := time.Now().Add(-time.Minute)
		if _, err := auth.Repo.UserSetLockoutState(ctx, user.ID, user.FailedLoginAttempts, &past, false); err != nil {
			t.Fatalf("failed to force lockout into the past: %v", err)
		}

		authenticated, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password})
		if err != nil {
			t.Fatalf("expected auto-unlock to allow login, got %v", err)
		}
		if !authenticated.IsActive || authenticated.FailedLoginAttempts != 0 {
			t.Fatalf("expected reset lockout state, got IsActive=%v attempts=%d", authenticated.IsActive, authenticated.FailedLoginAttempts)
		}
	})

	t.Run("a successful login resets the failed attempt counter", func(t *testing.T) {
		if err := wrongLogin(); err == nil {
			t.Fatal("expected error for wrong password")
		}
		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != nil {
			t.Fatalf("UserAuthenticate with correct password failed: %v", err)
		}
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.FailedLoginAttempts != 0 {
			t.Fatalf("expected failed attempt counter reset to 0, got %d", user.FailedLoginAttempts)
		}
	})
}

// TestAccountLockout_ExponentialBackoff proves repeated lockout cycles
// (fail -> lock -> window expires -> fail again) escalate the lockout
// duration instead of resetting to the same fixed window every time --
// otherwise a fixed-duration, purely account-keyed lockout is a
// repeatable, indefinite DoS: an attacker who only wants to deny a victim
// access can keep the account locked forever by sending MaxAttempts wrong
// guesses every LockoutDuration once it auto-expires.
func TestAccountLockout_ExponentialBackoff(t *testing.T) {
	const base = time.Minute
	auth := setupLockoutTestDB(t, 1, base) // MaxAttempts=1: every wrong guess locks immediately
	ctx := context.Background()

	email := util.UniqueEmail("backoff")
	password := "correct-horse-battery"
	if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	expireLockoutWindow := func(t *testing.T) {
		t.Helper()
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		past := time.Now().Add(-time.Second)
		if _, err := auth.Repo.UserSetLockoutState(ctx, user.ID, user.FailedLoginAttempts, &past, false); err != nil {
			t.Fatalf("failed to force lockout into the past: %v", err)
		}
	}

	lockedUntil := func(t *testing.T) time.Time {
		t.Helper()
		user, err := auth.Repo.UserGetByEmail(ctx, email)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if user.LockedUntil == nil {
			t.Fatal("expected the account to be locked")
		}
		return *user.LockedUntil
	}

	assertApprox := func(t *testing.T, label string, got time.Duration, want time.Duration) {
		t.Helper()
		delta := got - want
		if delta < 0 {
			delta = -delta
		}
		if delta > 5*time.Second {
			t.Errorf("%s: expected a lockout duration of ~%v, got %v", label, want, got)
		}
	}

	// First lockout: no prior cycles, duration is the configured base.
	before := time.Now()
	if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong"}); err == nil {
		t.Fatal("expected error for wrong password")
	}
	assertApprox(t, "1st lockout", lockedUntil(t).Sub(before), base)

	// Second cycle (window expired, then one more failure): duration doubles.
	expireLockoutWindow(t)
	before = time.Now()
	if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong"}); err == nil {
		t.Fatal("expected error for wrong password")
	}
	assertApprox(t, "2nd lockout", lockedUntil(t).Sub(before), 2*base)

	// Third cycle: doubles again.
	expireLockoutWindow(t)
	before = time.Now()
	if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong"}); err == nil {
		t.Fatal("expected error for wrong password")
	}
	assertApprox(t, "3rd lockout", lockedUntil(t).Sub(before), 4*base)

	// A successful login resets the counter, so the backoff also resets to
	// the base duration on the next cycle rather than continuing to escalate.
	expireLockoutWindow(t)
	if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("UserAuthenticate with correct password failed: %v", err)
	}
	before = time.Now()
	if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong"}); err == nil {
		t.Fatal("expected error for wrong password")
	}
	assertApprox(t, "post-success lockout", lockedUntil(t).Sub(before), base)
}

// TestRecordFailedLogin_ConcurrentCallsDoNotUndercount reproduces the race
// the atomic UserIncrementFailedLoginAttempts fix closes: two concurrent
// failed-login requests both read the same FailedLoginAttempts snapshot
// before either writes back. The old implementation computed
// "user.FailedLoginAttempts + 1" from that (possibly stale) in-memory value
// and wrote the absolute result, so both calls here would have written back
// 1, losing an increment. recordFailedLogin no longer reads the passed-in
// user's counter at all -- it increments atomically at the DB layer -- so
// calling it repeatedly with the very same stale snapshot must still land
// every increment.
func TestRecordFailedLogin_ConcurrentCallsDoNotUndercount(t *testing.T) {
	auth := setupLockoutTestDB(t, 100, time.Hour) // high threshold: this test isn't about lockout itself
	ctx := context.Background()

	email := util.UniqueEmail("lockout_race")
	if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: "correct-horse-battery"}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}
	staleUser, err := auth.Repo.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	const calls = 5
	for i := 0; i < calls; i++ {
		auth.recordFailedLogin(ctx, staleUser) // same stale snapshot every time, FailedLoginAttempts=0
	}

	updated, err := auth.Repo.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if updated.FailedLoginAttempts != calls {
		t.Fatalf("expected FailedLoginAttempts=%d after %d calls sharing a stale snapshot, got %d (lost updates -- read-modify-write race)", calls, calls, updated.FailedLoginAttempts)
	}
}

func TestAccountLockoutDisabledByDefault(t *testing.T) {
	auth := setupBasicAuthTestDB(t)
	ctx := context.Background()

	email := util.UniqueEmail("nolockout")
	password := "correct-horse-battery"
	if _, err := auth.UserCreate(ctx, &RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("UserCreate failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: "wrong"}); err == nil {
			t.Fatal("expected error for wrong password")
		}
	}

	if _, err := auth.UserAuthenticate(ctx, RequestBasicAuth{Email: email, Password: password}); err != nil {
		t.Fatalf("expected login to still succeed with lockout disabled, got %v", err)
	}
}
