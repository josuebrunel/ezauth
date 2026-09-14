package util

import "testing"

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
