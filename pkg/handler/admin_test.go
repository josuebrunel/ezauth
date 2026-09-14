package handler

import (
	"net/url"
	"testing"
)

func TestParseIntQueryParam(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantVal int
		wantErr bool
	}{
		{name: "missing value defaults to 0, no error", raw: "", wantVal: 0, wantErr: false},
		{name: "valid positive integer", raw: "50", wantVal: 50, wantErr: false},
		{name: "zero is valid", raw: "0", wantVal: 0, wantErr: false},
		{name: "malformed value is rejected", raw: "abc", wantErr: true},
		{name: "negative value is rejected", raw: "-1", wantErr: true},
		{name: "float value is rejected", raw: "1.5", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			if tc.raw != "" {
				q.Set("limit", tc.raw)
			}
			got, err := parseIntQueryParam(q, "limit", ErrInvalidLimitParam)
			if tc.wantErr {
				if err != ErrInvalidLimitParam {
					t.Fatalf("expected ErrInvalidLimitParam, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantVal {
				t.Fatalf("expected %d, got %d", tc.wantVal, got)
			}
		})
	}
}
