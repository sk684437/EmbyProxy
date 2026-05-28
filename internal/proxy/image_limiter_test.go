package proxy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestImageRequestLimiterSpacesStarts(t *testing.T) {
	interval := 25 * time.Millisecond
	limiter := newImageRequestLimiter(4, interval)
	release, err := limiter.acquire(context.Background(), "node")
	if err != nil {
		t.Fatal(err)
	}
	release()

	started := time.Now()
	release, err = limiter.acquire(context.Background(), "node")
	if err != nil {
		t.Fatal(err)
	}
	release()
	if elapsed := time.Since(started); elapsed < interval/2 {
		t.Fatalf("second image request started after %s, want at least %s", elapsed, interval/2)
	}
}

func TestImageRequestLimiterLimitsConcurrency(t *testing.T) {
	limiter := newImageRequestLimiter(1, 0)
	releaseFirst, err := limiter.acquire(context.Background(), "node")
	if err != nil {
		t.Fatal(err)
	}
	acquiredSecond := make(chan func(), 1)
	errs := make(chan error, 1)
	go func() {
		release, err := limiter.acquire(context.Background(), "node")
		if err != nil {
			errs <- err
			return
		}
		acquiredSecond <- release
	}()

	select {
	case release := <-acquiredSecond:
		release()
		t.Fatal("second image request acquired while first was still active")
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(20 * time.Millisecond):
	}

	releaseFirst()
	select {
	case release := <-acquiredSecond:
		release()
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("second image request did not acquire after first was released")
	}
}

func TestImageRequestLimiterBacksOffAfterRateLimit(t *testing.T) {
	limiter := newImageRequestLimiter(4, 0)
	backoff := 30 * time.Millisecond
	limiter.backoff("node", backoff)

	started := time.Now()
	release, err := limiter.acquire(context.Background(), "node")
	if err != nil {
		t.Fatal(err)
	}
	release()
	if elapsed := time.Since(started); elapsed < backoff/2 {
		t.Fatalf("image request started after %s, want backoff near %s", elapsed, backoff)
	}
}

func TestHandlerImageRequestLimiterDisabledByDefault(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	if limiter := h.ensureImageRequestLimiter(ctx); limiter != nil {
		t.Fatalf("default limiter = %+v, want nil", limiter)
	}
	release, err := h.acquireImageRequestSlot(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestHandlerImageRequestLimiterUsesSystemConfig(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))

	cfg := storage.DefaultSystemConfig()
	cfg.ImageProxyLimitEnabled = true
	cfg.ImageProxyMaxConcurrent = 1
	cfg.ImageProxyRequestIntervalMS = 20
	if err := store.SaveSystemConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	limiter := h.ensureImageRequestLimiter(ctx)
	if limiter.maxConcurrent != 1 || limiter.startInterval != 20*time.Millisecond {
		t.Fatalf("limiter = concurrent %d interval %s", limiter.maxConcurrent, limiter.startInterval)
	}

	cfg.ImageProxyMaxConcurrent = 3
	cfg.ImageProxyRequestIntervalMS = 0
	if err := store.SaveSystemConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	updated := h.ensureImageRequestLimiter(ctx)
	if updated == limiter {
		t.Fatal("limiter was not rebuilt after config change")
	}
	if updated.maxConcurrent != 3 || updated.startInterval != 0 {
		t.Fatalf("updated limiter = concurrent %d interval %s", updated.maxConcurrent, updated.startInterval)
	}
}

func newProxyTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}
