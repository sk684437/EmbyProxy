package requestlog

import (
	"context"
	"sync"
	"sync/atomic"
)

type accessLogStateKey struct{}

type accessLogState struct {
	suppressed atomic.Bool
	mu         sync.Mutex
	requestURI string
}

func WithAccessLogState(ctx context.Context) context.Context {
	if state(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, accessLogStateKey{}, &accessLogState{})
}

func SuppressAccessLog(ctx context.Context) {
	st := state(ctx)
	if st == nil {
		return
	}
	st.suppressed.Store(true)
}

func AccessLogSuppressed(ctx context.Context) bool {
	st := state(ctx)
	return st != nil && st.suppressed.Load()
}

func SetRequestURI(ctx context.Context, uri string) {
	st := state(ctx)
	if st == nil || uri == "" {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.requestURI = uri
}

func RequestURI(ctx context.Context) (string, bool) {
	st := state(ctx)
	if st == nil {
		return "", false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.requestURI, st.requestURI != ""
}

func state(ctx context.Context) *accessLogState {
	if ctx == nil {
		return nil
	}
	st, _ := ctx.Value(accessLogStateKey{}).(*accessLogState)
	return st
}
