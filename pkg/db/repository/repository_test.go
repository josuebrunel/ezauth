package repository

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpen_RejectsUnknownDialect(t *testing.T) {
	_, err := Open(Opts{Dialect: "postgress", DSN: "irrelevant"})
	if err == nil {
		t.Fatal("expected an error for an unrecognized dialect, got nil")
	}
	if !strings.Contains(err.Error(), "postgress") {
		t.Errorf("expected the error to name the bad dialect, got: %v", err)
	}
}

func TestOpen_AcceptsSqliteAliases(t *testing.T) {
	for _, dialect := range []string{"sqlite", "sqlite3", ""} {
		t.Run(dialect, func(t *testing.T) {
			repo, err := Open(Opts{Dialect: dialect, DSN: "file::memory:?cache=shared"})
			if err != nil {
				t.Fatalf("Open(%q) unexpected error: %v", dialect, err)
			}
			defer repo.Close()
		})
	}
}

func TestNew_AppliesPoolDefaults(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	// database/sql's own default is unlimited open connections -- confirm
	// New overrides it rather than a caller silently inheriting that default.
	repo := New(db, "sqlite")
	defer repo.Close()

	stats := db.Stats()
	if stats.MaxOpenConnections != defaultMaxOpenConns {
		t.Errorf("expected MaxOpenConnections %d after New, got %d", defaultMaxOpenConns, stats.MaxOpenConnections)
	}
}

func TestQuotePostgresIdentifier(t *testing.T) {
	cases := map[string]string{
		"myschema":   `"myschema"`,
		"order":      `"order"`,       // a reserved word -- must still quote cleanly
		"MySchema":   `"MySchema"`,    // case preserved inside quotes
		`with"quote`: `"with""quote"`, // embedded quote doubled, per standard SQL escaping
	}
	for in, want := range cases {
		if got := quotePostgresIdentifier(in); got != want {
			t.Errorf("quotePostgresIdentifier(%q) = %q, want %q", in, got, want)
		}
	}
}
