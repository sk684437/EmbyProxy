package storage

import (
	"context"
	"database/sql"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"embyproxy/internal/localtime"
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

func TestLogPlaybackCountsDistinctMediaWithinSession(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	headers := http.Header{
		"User-Agent":        {"session-client"},
		"X-Emby-Device-Id":  {"device-1"},
		"X-Emby-Session-Id": {"session-1"},
	}
	base := time.Date(2026, 6, 8, 9, 0, 0, 0, localtime.Location()).UnixMilli()
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
		OccurredAt: base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(first) error = %v", err)
	}
	traffic := input
	traffic.TrafficOnly = true
	traffic.InboundBytes = 1024
	traffic.OutboundBytes = 1024
	if err := store.LogPlaybackTraffic(ctx, traffic); err != nil {
		t.Fatalf("LogPlaybackTraffic(first) error = %v", err)
	}
	input.RequestURL = "/emby/videos/1/stream.m3u8"
	input.OccurredAt = base + int64(time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(repeat) error = %v", err)
	}
	traffic = input
	traffic.TrafficOnly = true
	traffic.InboundBytes = 1024
	traffic.OutboundBytes = 1024
	if err := store.LogPlaybackTraffic(ctx, traffic); err != nil {
		t.Fatalf("LogPlaybackTraffic(repeat) error = %v", err)
	}
	input.RequestURL = "/emby/videos/2/stream"
	input.OccurredAt = base + int64(2*time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(second media) error = %v", err)
	}
	traffic = input
	traffic.TrafficOnly = true
	traffic.InboundBytes = 1024
	traffic.OutboundBytes = 1024
	if err := store.LogPlaybackTraffic(ctx, traffic); err != nil {
		t.Fatalf("LogPlaybackTraffic(second media) error = %v", err)
	}

	var plays, sessions, bytes int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0), COALESCE(SUM(bytes), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "session-client").Scan(&plays, &sessions, &bytes); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 2 || sessions != 1 || bytes != 3072 {
		t.Fatalf("play_stats = plays %d sessions %d bytes %d; want 2, 1, 3072", plays, sessions, bytes)
	}
}

func TestLogPlaybackDoesNotCountHeadResponseBytes(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	input := PlaybackInput{
		Node:       Node{Name: "alpha"},
		RequestIP:  "127.0.0.1",
		Headers:    http.Header{"User-Agent": {"head-client"}},
		Status:     http.StatusOK,
		RespHeader: http.Header{"Content-Length": {"10737418240"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/videos/1/stream",
		Method:     http.MethodHead,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback() error = %v", err)
	}

	var plays, sessions, bytes int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0), COALESCE(SUM(bytes), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "head-client").Scan(&plays, &sessions, &bytes); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 1 || sessions != 1 || bytes != 0 {
		t.Fatalf("play_stats = plays %d sessions %d bytes %d; want 1, 1, 0", plays, sessions, bytes)
	}
}

func TestLogPlaybackTrafficCountsReadAndWriteBytes(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	input := PlaybackInput{
		Node:      Node{Name: "alpha"},
		RequestIP: "127.0.0.1",
		Headers:   http.Header{"User-Agent": {"range-client"}},
		Status:    http.StatusPartialContent,
		RespHeader: http.Header{
			"Content-Length": {"4096"},
			"Content-Range":  {"bytes 1024-2047/4096"},
		},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/videos/1/stream",
		Method:     http.MethodGet,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback() error = %v", err)
	}
	traffic := input
	traffic.TrafficOnly = true
	traffic.InboundBytes = 768
	traffic.OutboundBytes = 512
	if err := store.LogPlaybackTraffic(ctx, traffic); err != nil {
		t.Fatalf("LogPlaybackTraffic() error = %v", err)
	}

	var bytes, inboundBytes, outboundBytes int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(bytes), 0), COALESCE(SUM(inbound_bytes), 0), COALESCE(SUM(outbound_bytes), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "range-client").Scan(&bytes, &inboundBytes, &outboundBytes); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if bytes != 512 || inboundBytes != 768 || outboundBytes != 512 {
		t.Fatalf("play_stats bytes = %d inbound = %d outbound = %d; want 512, 768, 512", bytes, inboundBytes, outboundBytes)
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

func TestLogPlaybackAsyncUsesOccurredAtForStatsTime(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	occurredAt := time.Date(2000, 1, 2, 16, 0, 1, 0, time.UTC).UnixMilli()
	input := PlaybackInput{
		Node:       Node{Name: "occurred"},
		RequestIP:  "127.0.0.1",
		Headers:    http.Header{"User-Agent": {"time-client"}},
		Status:     http.StatusOK,
		RespHeader: http.Header{"Content-Length": {"4096"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/videos/3/stream",
		Method:     http.MethodGet,
		OccurredAt: occurredAt,
	}
	if ok := store.LogPlaybackAsync(input); !ok {
		t.Fatal("LogPlaybackAsync() returned false")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		var day string
		var updatedAt int64
		err := store.db.QueryRowContext(ctx, `
			SELECT day, updated_at
			FROM play_stats
			WHERE node = ? AND client = ?
		`, "occurred", "time-client").Scan(&day, &updatedAt)
		if err == nil && day == "2000-01-03" && updatedAt == occurredAt {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("async playback stat used wrong time; day=%q updatedAt=%d err=%v", day, updatedAt, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	var lastPlayAt int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT last_play_ts FROM keepalive_state WHERE node = ?
	`, "admin:occurred").Scan(&lastPlayAt); err != nil {
		t.Fatalf("query keepalive_state error = %v", err)
	}
	if lastPlayAt != occurredAt {
		t.Fatalf("last_play_ts = %d; want %d", lastPlayAt, occurredAt)
	}

	var counter string
	var counterUpdatedAt int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT v, updated_at FROM proxy_kv WHERE k = ?
	`, "stats:proxyPlays:2000-01-03").Scan(&counter, &counterUpdatedAt); err != nil {
		t.Fatalf("query proxy play counter error = %v", err)
	}
	if counter != "1" || counterUpdatedAt != occurredAt {
		t.Fatalf("proxy play counter = %q updatedAt=%d; want 1 updatedAt=%d", counter, counterUpdatedAt, occurredAt)
	}
}

func TestGetPlayStatsUsesUTC8CalendarWindow(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	now := localtime.Now()
	today := now.Format("2006-01-02")
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
	for _, row := range []struct {
		day   string
		node  string
		plays int64
	}{
		{day: today, node: "today", plays: 2},
		{day: yesterday, node: "yesterday", plays: 1},
	} {
		if _, err := store.db.ExecContext(ctx, `
			INSERT INTO play_stats (day, node, client, plays, bytes, sessions, errors, updated_at)
			VALUES (?, ?, ?, ?, 0, ?, 0, ?)
		`, row.day, row.node, "client", row.plays, row.plays, now.UnixMilli()); err != nil {
			t.Fatalf("insert %s stat error = %v", row.node, err)
		}
	}

	stats, err := store.GetPlayStats(ctx, 1)
	if err != nil {
		t.Fatalf("GetPlayStats(1) error = %v", err)
	}
	if len(stats) != 1 || stats[0].Day != today || stats[0].Node != "today" {
		t.Fatalf("GetPlayStats(1) = %+v; want only today's row", stats)
	}

	stats, err = store.GetPlayStats(ctx, 7)
	if err != nil {
		t.Fatalf("GetPlayStats(7) error = %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("GetPlayStats(7) len = %d; want 2 rows: %+v", len(stats), stats)
	}
}

func TestInitSchemaDoesNotPromoteLegacyPlayStatsBytes(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE play_stats (
			day TEXT NOT NULL,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			plays INTEGER DEFAULT 0,
			bytes INTEGER DEFAULT 0,
			sessions INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(day, node, client)
		);
		INSERT INTO play_stats (day, node, client, plays, bytes, sessions, errors, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?);
	`, localtime.Now().Format("2006-01-02"), "legacy", "client", 1, int64(1234), 1, 0, localtime.Now().UnixMilli()); err != nil {
		_ = db.Close()
		t.Fatalf("create legacy schema error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("legacy db close error = %v", err)
	}

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	stats, err := store.GetPlayStats(ctx, 1)
	if err != nil {
		t.Fatalf("GetPlayStats() error = %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("stats len = %d; want 1: %+v", len(stats), stats)
	}
	if stats[0].Bytes != 1234 || stats[0].OutboundBytes != 0 || stats[0].InboundBytes != 0 {
		t.Fatalf("migrated traffic = bytes %d inbound %d outbound %d; want 1234, 0, 0", stats[0].Bytes, stats[0].InboundBytes, stats[0].OutboundBytes)
	}
}
