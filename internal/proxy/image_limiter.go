package proxy

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	imageProxyMaxConcurrent  = 4
	imageProxyStartInterval  = 250 * time.Millisecond
	imageProxyDefaultBackoff = 10 * time.Second
	imageProxyMaxBackoff     = 30 * time.Second
)

type imageRequestLimiter struct {
	mu            sync.Mutex
	states        map[string]*imageRequestLimitState
	maxConcurrent int
	startInterval time.Duration
}

type imageRequestLimitState struct {
	sem          chan struct{}
	mu           sync.Mutex
	next         time.Time
	backoffUntil time.Time
}

func newImageRequestLimiter(maxConcurrent int, startInterval time.Duration) *imageRequestLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	return &imageRequestLimiter{
		states:        map[string]*imageRequestLimitState{},
		maxConcurrent: maxConcurrent,
		startInterval: startInterval,
	}
}

func (h *Handler) acquireImageRequestSlot(ctx context.Context, nodeName string) (func(), error) {
	limiter := h.ensureImageRequestLimiter()
	return limiter.acquire(ctx, nodeName)
}

func (h *Handler) noteImageRateLimited(nodeName, retryAfter string) time.Duration {
	limiter := h.ensureImageRequestLimiter()
	return limiter.noteRateLimited(nodeName, retryAfter)
}

func (h *Handler) ensureImageRequestLimiter() *imageRequestLimiter {
	h.imageLimiterMu.Lock()
	defer h.imageLimiterMu.Unlock()
	limiter := h.imageLimiter
	if limiter == nil {
		limiter = newImageRequestLimiter(imageProxyMaxConcurrent, imageProxyStartInterval)
		h.imageLimiter = limiter
	}
	return limiter
}

func (l *imageRequestLimiter) acquire(ctx context.Context, key string) (func(), error) {
	if l == nil {
		return func() {}, nil
	}
	state := l.state(key)
	select {
	case state.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := l.waitStartTurn(ctx, state); err != nil {
		<-state.sem
		return nil, err
	}
	return func() {
		<-state.sem
	}, nil
}

func (l *imageRequestLimiter) state(key string) *imageRequestLimitState {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		key = "-"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.states[key]
	if state == nil {
		state = &imageRequestLimitState{sem: make(chan struct{}, l.maxConcurrent)}
		l.states[key] = state
	}
	return state
}

func (l *imageRequestLimiter) waitStartTurn(ctx context.Context, state *imageRequestLimitState) error {
	for {
		state.mu.Lock()
		next := state.next
		if state.backoffUntil.After(next) {
			next = state.backoffUntil
		}
		if wait := time.Until(next); wait > 0 {
			state.mu.Unlock()
			if err := sleepWithContext(ctx, wait); err != nil {
				return err
			}
			continue
		}
		if l.startInterval > 0 {
			state.next = time.Now().Add(l.startInterval)
		}
		state.mu.Unlock()
		return nil
	}
}

func (l *imageRequestLimiter) noteRateLimited(key, retryAfter string) time.Duration {
	duration := parseRetryAfterDuration(retryAfter, time.Now())
	if duration <= 0 {
		duration = imageProxyDefaultBackoff
	}
	if duration > imageProxyMaxBackoff {
		duration = imageProxyMaxBackoff
	}
	return l.backoff(key, duration)
}

func (l *imageRequestLimiter) backoff(key string, duration time.Duration) time.Duration {
	if l == nil || duration <= 0 {
		return 0
	}
	state := l.state(key)
	until := time.Now().Add(duration)
	state.mu.Lock()
	if until.After(state.backoffUntil) {
		state.backoffUntil = until
	}
	state.mu.Unlock()
	return duration
}

func parseRetryAfterDuration(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	return when.Sub(now)
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return ctx.Err()
	}
}
