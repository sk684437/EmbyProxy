package proxy

import (
	"context"
	"sync"
	"time"

	"embyproxy/internal/storage"
)

type playbackLogStateKey struct{}

type playbackLogState struct {
	mu         sync.Mutex
	in         storage.PlaybackInput
	has        bool
	occurredAt int64
}

func withPlaybackLogState(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Value(playbackLogStateKey{}).(*playbackLogState); ok {
		return ctx
	}
	return context.WithValue(ctx, playbackLogStateKey{}, &playbackLogState{occurredAt: time.Now().UnixMilli()})
}

func playbackRequestOccurredAt(ctx context.Context) int64 {
	state, ok := ctx.Value(playbackLogStateKey{}).(*playbackLogState)
	if !ok || state.occurredAt <= 0 {
		return time.Now().UnixMilli()
	}
	return state.occurredAt
}

func registerPlaybackLog(ctx context.Context, in storage.PlaybackInput) bool {
	state, ok := ctx.Value(playbackLogStateKey{}).(*playbackLogState)
	if !ok {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.in = in
	state.has = true
	return true
}

func takePlaybackTrafficLog(ctx context.Context, inboundBytes, outboundBytes int64) (storage.PlaybackInput, bool) {
	state, ok := ctx.Value(playbackLogStateKey{}).(*playbackLogState)
	if !ok {
		return storage.PlaybackInput{}, false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.has {
		return storage.PlaybackInput{}, false
	}
	if inboundBytes < 0 {
		inboundBytes = 0
	}
	if outboundBytes < 0 {
		outboundBytes = 0
	}
	in := state.in
	in.TrafficOnly = true
	in.InboundBytes = inboundBytes
	in.OutboundBytes = outboundBytes
	state.has = false
	state.in = storage.PlaybackInput{}
	return in, true
}
