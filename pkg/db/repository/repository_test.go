package repository

import (
	"strings"
	"testing"
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
