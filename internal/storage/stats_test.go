package storage

import (
	"context"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLogPlaybackConcurrentSessionDedup(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	headers := http.Header{
		"User-Agent":        {"test-client"},
		"X-Emby-Device-Id":  {"device-1"},
		"X-Emby-Session-Id": {"session-1"},
	}
	input := PlaybackInput{
		Node:       Node{Name: "alpha"},
		RequestIP:  "127.0.0.1",
		Headers:    headers,
		Status:     http.StatusOK,
		RespHeader: http.Header{"Content-Length": {"1024"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/videos/1/stream",
		Method:     http.MethodGet,
	}

	const calls = 20
	var wg sync.WaitGroup
	errs := make(chan error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.LogPlayback(ctx, input)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("LogPlayback() error = %v", err)
		}
	}

	var plays, sessions int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "test-client").Scan(&plays, &sessions); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 1 || sessions != 1 {
		t.Fatalf("play_stats = plays %d, sessions %d; want 1, 1", plays, sessions)
	}

	var counter string
	if err := store.db.QueryRowContext(ctx, `
		SELECT v FROM proxy_kv WHERE k LIKE 'stats:proxyPlays:%'
	`).Scan(&counter); err != nil {
		t.Fatalf("query proxy play counter error = %v", err)
	}
	if counter != "1" {
		t.Fatalf("proxy play counter = %q; want 1", counter)
	}
}

func TestLogPlaybackAsyncDoesNotWaitForDatabase(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx() error = %v", err)
	}

	input := PlaybackInput{
		Node:       Node{Name: "async"},
		RequestIP:  "127.0.0.1",
		Headers:    http.Header{"User-Agent": {"async-client"}},
		Status:     http.StatusOK,
		RespHeader: http.Header{"Content-Length": {"2048"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/videos/2/stream",
		Method:     http.MethodGet,
	}

	started := time.Now()
	if ok := store.LogPlaybackAsync(input); !ok {
		t.Fatal("LogPlaybackAsync() returned false")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("LogPlaybackAsync() took %s; want it to avoid waiting for the database", elapsed)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		var plays int64
		err := store.db.QueryRowContext(ctx, `
			SELECT COALESCE(SUM(plays), 0)
			FROM play_stats
			WHERE node = ? AND client = ?
		`, "async", "async-client").Scan(&plays)
		if err == nil && plays == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("async playback stat was not written in time; plays=%d err=%v", plays, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
