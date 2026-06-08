package localtime

import "time"

// Location is the fixed UTC+8 timezone used for user-facing system times.
var Location = time.FixedZone("UTC+8", 8*60*60)

func Now() time.Time {
	return time.Now().In(Location)
}

func FromUnixMilli(ts int64) time.Time {
	return time.UnixMilli(ts).In(Location)
}

func Format(t time.Time, layout string) string {
	return t.In(Location).Format(layout)
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
