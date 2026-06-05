package proxy

import (
	"context"
	"sync"
	"time"
)

type accessLogFieldsKey struct{}

type accessLogFields struct {
	mu                   sync.Mutex
	values               map[string]any
	responseBodyStart    time.Time
	hasResponseBodyStart bool
}

func WithAccessLogFields(ctx context.Context) context.Context {
	return context.WithValue(ctx, accessLogFieldsKey{}, &accessLogFields{values: map[string]any{}})
}

func SetAccessLogField(ctx context.Context, key string, value any) {
	fields, ok := ctx.Value(accessLogFieldsKey{}).(*accessLogFields)
	if !ok || key == "" {
		return
	}
	fields.mu.Lock()
	defer fields.mu.Unlock()
	fields.values[key] = value
}

func AccessLogFields(ctx context.Context) map[string]any {
	fields, ok := ctx.Value(accessLogFieldsKey{}).(*accessLogFields)
	if !ok {
		return nil
	}
	fields.mu.Lock()
	defer fields.mu.Unlock()
	out := make(map[string]any, len(fields.values))
	for key, value := range fields.values {
		out[key] = value
	}
	return out
}

// MarkAccessLogResponseBodyStart records when downstream response delivery begins.
func MarkAccessLogResponseBodyStart(ctx context.Context, started time.Time) {
	fields, ok := ctx.Value(accessLogFieldsKey{}).(*accessLogFields)
	if !ok || started.IsZero() {
		return
	}
	fields.mu.Lock()
	defer fields.mu.Unlock()
	fields.responseBodyStart = started
	fields.hasResponseBodyStart = true
}

// AccessLogResponseBodyStart returns the recorded downstream response start time.
func AccessLogResponseBodyStart(ctx context.Context) (time.Time, bool) {
	fields, ok := ctx.Value(accessLogFieldsKey{}).(*accessLogFields)
	if !ok {
		return time.Time{}, false
	}
	fields.mu.Lock()
	defer fields.mu.Unlock()
	return fields.responseBodyStart, fields.hasResponseBodyStart
}

func withAccessLogFields(ctx context.Context, meta map[string]any) map[string]any {
	fields := AccessLogFields(ctx)
	if len(fields) == 0 {
		return meta
	}
	out := make(map[string]any, len(meta)+len(fields))
	for key, value := range meta {
		out[key] = value
	}
	for key, value := range fields {
		out[key] = value
	}
	return out
}
