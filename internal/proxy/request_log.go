package proxy

import (
	"context"
	"sync"
)

type accessLogFieldsKey struct{}

type accessLogFields struct {
	mu     sync.Mutex
	values map[string]any
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
