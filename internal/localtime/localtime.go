package localtime

import (
	"os"
	"strings"
	"sync"
	"time"
)

const EnvName = "TZ"

var (
	defaultLocation = time.FixedZone("UTC+8", 8*60*60)
	locationCache   = struct {
		sync.RWMutex
		env string
		loc *time.Location
	}{loc: defaultLocation}
)

func Location() *time.Location {
	env := strings.TrimSpace(os.Getenv(EnvName))

	locationCache.RLock()
	if locationCache.loc != nil && locationCache.env == env {
		loc := locationCache.loc
		locationCache.RUnlock()
		return loc
	}
	locationCache.RUnlock()

	loc := resolveLocation(env)
	locationCache.Lock()
	locationCache.env = env
	locationCache.loc = loc
	locationCache.Unlock()
	return loc
}

func Now() time.Time {
	return time.Now().In(Location())
}

func FromUnixMilli(ts int64) time.Time {
	return time.UnixMilli(ts).In(Location())
}

func Format(t time.Time, layout string) string {
	return t.In(Location()).Format(layout)
}

func FormatUnixMilli(ts int64, layout string) string {
	return FromUnixMilli(ts).Format(layout)
}

func Date(ts int64) string {
	return FormatUnixMilli(ts, "2006-01-02")
}

func HHMM(ts int64) string {
	return FormatUnixMilli(ts, "15:04")
}

func RFC3339(t time.Time) string {
	return Format(t, time.RFC3339)
}

func resolveLocation(env string) *time.Location {
	if env == "" {
		return defaultLocation
	}
	if loc, err := time.LoadLocation(env); err == nil {
		return loc
	}
	return defaultLocation
}
