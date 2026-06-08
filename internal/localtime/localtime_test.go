package localtime

import (
	"testing"
	"time"
)

func TestFormatDefaultsToUTC8WhenTZIsEmpty(t *testing.T) {
	t.Setenv(EnvName, "")

	got := RFC3339(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC))
	if got != "2000-01-02T08:00:00+08:00" {
		t.Fatalf("RFC3339() = %q, want UTC+8 default", got)
	}
}

func TestFormatUsesNamedTZ(t *testing.T) {
	t.Setenv(EnvName, "UTC")

	got := RFC3339(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC))
	if got != "2000-01-02T00:00:00Z" {
		t.Fatalf("RFC3339() = %q, want UTC", got)
	}
}

func TestFormatFallsBackToUTC8ForInvalidTZ(t *testing.T) {
	t.Setenv(EnvName, "not-a-time-zone")

	got := RFC3339(time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC))
	if got != "2000-01-02T08:00:00+08:00" {
		t.Fatalf("RFC3339() = %q, want UTC+8 fallback", got)
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
