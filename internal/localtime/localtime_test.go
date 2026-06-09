package localtime

import (
	"testing"
	"time"
)

func TestFormatUsesConfiguredTZWithUTC8Fallback(t *testing.T) {
	tests := []struct {
		name string
		tz   string
		want string
	}{
		{name: "empty defaults to UTC+8", tz: "", want: "2000-01-02T08:00:00+08:00"},
		{name: "named timezone", tz: "UTC", want: "2000-01-02T00:00:00Z"},
		{name: "invalid timezone falls back to UTC+8", tz: "not-a-time-zone", want: "2000-01-02T08:00:00+08:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvName, tt.tz)

			got := RFC3339(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC))
			if got != tt.want {
				t.Fatalf("RFC3339() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLocationRefreshesWhenTZChanges(t *testing.T) {
	t.Setenv(EnvName, "UTC")
	if got := RFC3339(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)); got != "2000-01-02T00:00:00Z" {
		t.Fatalf("RFC3339() with UTC = %q", got)
	}

	t.Setenv(EnvName, "Asia/Tokyo")
	if got := RFC3339(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)); got != "2000-01-02T09:00:00+09:00" {
		t.Fatalf("RFC3339() after TZ change = %q", got)
	}
}
