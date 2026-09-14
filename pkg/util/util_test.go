package util

import "testing"

func TestRandomString(t *testing.T) {
	s, err := RandomString(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 32 {
		t.Fatalf("expected a 32-char hex string, got %d chars: %q", len(s), s)
	}
	if _, err := RandomString(31); err != nil {
		t.Fatalf("unexpected error for odd length: %v", err)
	}
	s2, err := RandomString(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == s2 {
		t.Fatal("expected two calls to produce different random values")
	}
}

func TestRedactDSN(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
		want string
	}{
		{
			name: "postgres URL DSN",
			dsn:  "postgres://myuser:s3cr3t@localhost:5432/mydb?sslmode=disable",
			want: "postgres://myuser:***@localhost:5432/mydb?sslmode=disable",
		},
		{
			name: "mysql driver DSN",
			dsn:  "myuser:s3cr3t@tcp(localhost:3306)/mydb?parseTime=true",
			want: "myuser:***@tcp(localhost:3306)/mydb?parseTime=true",
		},
		{
			name: "libpq key=value DSN",
			dsn:  "host=localhost user=myuser password=s3cr3t dbname=mydb sslmode=disable",
			want: "host=localhost user=myuser password=*** dbname=mydb sslmode=disable",
		},
		{
			name: "libpq key=value DSN with pwd alias",
			dsn:  "host=localhost user=myuser pwd=s3cr3t dbname=mydb",
			want: "host=localhost user=myuser pwd=*** dbname=mydb",
		},
		{
			name: "sqlite path has no credentials",
			dsn:  "file:test.db?mode=memory&cache=shared",
			want: "file:test.db?mode=memory&cache=shared",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactDSN(tc.dsn)
			if got != tc.want {
				t.Fatalf("RedactDSN(%q) = %q, want %q", tc.dsn, got, tc.want)
			}
			if got == tc.dsn && tc.dsn != tc.want {
				t.Fatalf("RedactDSN(%q) did not redact anything", tc.dsn)
			}
		})
	}
}

func TestEscapeLikePattern(t *testing.T) {
	cases := map[string]string{
		"plain":     "plain",
		"50%_off":   "50!%!_off",
		"a!b":       "a!!b",
		"":          "",
		"_leading":  "!_leading",
		"trailing%": "trailing!%",
	}

	for in, want := range cases {
		if got := EscapeLikePattern(in); got != want {
			t.Fatalf("EscapeLikePattern(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHashToken(t *testing.T) {
	const raw = "some-high-entropy-refresh-token-value"

	got := HashToken(raw)

	if got == raw {
		t.Fatal("HashToken returned the input unchanged")
	}
	if len(got) != 64 { // 32-byte SHA-256 digest, hex-encoded
		t.Fatalf("expected a 64-char hex digest, got %d chars: %q", len(got), got)
	}
	if got2 := HashToken(raw); got != got2 {
		t.Fatalf("HashToken is not deterministic: %q != %q", got, got2)
	}
	if HashToken("a-different-value") == got {
		t.Fatal("expected different inputs to hash differently")
	}
}
