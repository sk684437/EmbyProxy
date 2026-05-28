package proxy

import (
	"context"
	"testing"
	"time"
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
