package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"embyproxy/internal/localtime"
)

func TestLogPlaybackConcurrentSessionDedup(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	headers := http.Header{
		"User-Agent":        {"test-client"},
		"X-Emby-Device-Id":  {"device-1"},
		"X-Emby-Session-Id": {"session-1"},
	}
	input := PlaybackInput{
		Node:       Node{Name: "alpha"},
		RequestIP:  "127.0.0.1",
		Headers:    headers,
		Status:     http.StatusNoContent,
		RespHeader: http.Header{"Content-Length": {"1024"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/Sessions/Playing",
		Method:     http.MethodPost,
		RequestBody: []byte(`{
			"ItemId": "1",
			"SessionId": "session-1",
			"PlaySessionId": "play-session-1"
		}`),
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
	store := newStatsTestStore(t)

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
		Status:     http.StatusNoContent,
		RespHeader: http.Header{"Content-Length": {"1024"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/Sessions/Playing",
		Method:     http.MethodPost,
		RequestBody: []byte(`{
			"ItemId": "1",
			"SessionId": "session-1",
			"PlaySessionId": "play-session-1"
		}`),
		OccurredAt: base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(first) error = %v", err)
	}
	traffic := input
	traffic.TrafficOnly = true
	traffic.RequestURL = "/emby/videos/1/stream"
	traffic.Method = http.MethodGet
	traffic.InboundBytes = 1024
	traffic.OutboundBytes = 1024
	if err := store.LogPlaybackTraffic(ctx, traffic); err != nil {
		t.Fatalf("LogPlaybackTraffic(first) error = %v", err)
	}
	input.RequestURL = "/emby/Sessions/Playing"
	input.Method = http.MethodPost
	input.OccurredAt = base + int64(time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(repeat) error = %v", err)
	}
	traffic = input
	traffic.TrafficOnly = true
	traffic.RequestURL = "/emby/videos/1/stream.m3u8"
	traffic.Method = http.MethodGet
	traffic.InboundBytes = 1024
	traffic.OutboundBytes = 1024
	if err := store.LogPlaybackTraffic(ctx, traffic); err != nil {
		t.Fatalf("LogPlaybackTraffic(repeat) error = %v", err)
	}
	input.RequestBody = []byte(`{
		"ItemId": "2",
		"SessionId": "session-1",
		"PlaySessionId": "play-session-2"
	}`)
	input.OccurredAt = base + int64(2*time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(second media) error = %v", err)
	}
	traffic = input
	traffic.TrafficOnly = true
	traffic.RequestURL = "/emby/videos/2/stream"
	traffic.Method = http.MethodGet
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
	if plays != 2 || sessions != 1 || bytes != 6144 {
		t.Fatalf("play_stats = plays %d sessions %d bytes %d; want 2, 1, 6144", plays, sessions, bytes)
	}
}

func TestLogPlaybackDedupsSessionsAcrossMediaSessionIDs(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	headers := http.Header{
		"User-Agent":       {"session-client"},
		"X-Emby-Device-Id": {"device-1"},
	}
	base := time.Date(2026, 6, 8, 9, 0, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:       Node{Name: "alpha"},
		RequestIP:  "127.0.0.1",
		Headers:    headers,
		Status:     http.StatusNoContent,
		IsPlayback: true,
		Mode:       "proxy",
		Method:     http.MethodPost,
		RequestURL: "/emby/Sessions/Playing",
		OccurredAt: base,
	}
	for idx, body := range [][]byte{
		[]byte(`{"ItemId":"3197063","SessionId":"session-1","MediaSourceId":"mediasource_3197063","PlaySessionId":"play-session-1"}`),
		[]byte(`{"ItemId":"3407103","SessionId":"session-2","MediaSourceId":"mediasource_3407141","PlaySessionId":"play-session-2"}`),
	} {
		input.RequestBody = body
		input.OccurredAt = base + int64(idx)*int64(time.Minute/time.Millisecond)
		if err := store.LogPlayback(ctx, input); err != nil {
			t.Fatalf("LogPlayback(%d) error = %v", idx, err)
		}
	}

	var plays, sessions int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "session-client").Scan(&plays, &sessions); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 2 || sessions != 1 {
		t.Fatalf("play_stats = plays %d sessions %d; want 2, 1", plays, sessions)
	}
}

func TestLogPlaybackDedupsSessionAcrossMidnight(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	headers := http.Header{
		"User-Agent":       {"night-client"},
		"X-Emby-Device-Id": {"device-1"},
	}
	base := time.Date(2026, 6, 8, 23, 58, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:       Node{Name: "alpha"},
		RequestIP:  "127.0.0.1",
		Headers:    headers,
		Status:     http.StatusNoContent,
		IsPlayback: true,
		Mode:       "proxy",
		Method:     http.MethodPost,
		RequestURL: "/emby/Sessions/Playing",
		OccurredAt: base,
	}
	for idx, body := range [][]byte{
		[]byte(`{"ItemId":"night-1","SessionId":"session-1","PlaySessionId":"play-session-1"}`),
		[]byte(`{"ItemId":"night-2","SessionId":"session-2","PlaySessionId":"play-session-2"}`),
	} {
		input.RequestBody = body
		input.OccurredAt = base + int64(idx)*5*int64(time.Minute/time.Millisecond)
		if err := store.LogPlayback(ctx, input); err != nil {
			t.Fatalf("LogPlayback(%d) error = %v", idx, err)
		}
	}

	var plays, sessions int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "night-client").Scan(&plays, &sessions); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 2 || sessions != 1 {
		t.Fatalf("play_stats = plays %d sessions %d; want 2, 1", plays, sessions)
	}
}

func TestLogPlaybackProgressRefreshesSessionDedupWindow(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	headers := http.Header{
		"User-Agent":       {"progress-client"},
		"X-Emby-Device-Id": {"device-1"},
	}
	base := time.Date(2026, 6, 8, 9, 0, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:        Node{Name: "alpha"},
		RequestIP:   "127.0.0.1",
		Headers:     headers,
		Status:      http.StatusNoContent,
		IsPlayback:  true,
		Mode:        "proxy",
		Method:      http.MethodPost,
		RequestURL:  "/emby/Sessions/Playing",
		RequestBody: []byte(`{"ItemId":"item-1","SessionId":"session-1","PlaySessionId":"play-session-1"}`),
		OccurredAt:  base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(start) error = %v", err)
	}

	input.RequestURL = "/emby/Sessions/Playing/Progress"
	input.RequestBody = []byte(`{"ItemId":"item-1","SessionId":"session-1","PlaySessionId":"play-session-1"}`)
	input.OccurredAt = base + int64(20*time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(progress) error = %v", err)
	}

	input.RequestURL = "/emby/Sessions/Playing"
	input.RequestBody = []byte(`{"ItemId":"item-2","SessionId":"session-2","PlaySessionId":"play-session-2"}`)
	input.OccurredAt = base + int64(21*time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(next) error = %v", err)
	}

	var plays, sessions int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "progress-client").Scan(&plays, &sessions); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 2 || sessions != 1 {
		t.Fatalf("play_stats = plays %d sessions %d; want 2, 1", plays, sessions)
	}
}

func TestLogPlaybackStoppedRefreshesSessionDedupWindow(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	headers := http.Header{
		"User-Agent":       {"stopped-client"},
		"X-Emby-Device-Id": {"device-1"},
	}
	base := time.Date(2026, 6, 8, 9, 0, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:        Node{Name: "alpha"},
		RequestIP:   "127.0.0.1",
		Headers:     headers,
		Status:      http.StatusNoContent,
		IsPlayback:  true,
		Mode:        "proxy",
		Method:      http.MethodPost,
		RequestURL:  "/emby/Sessions/Playing",
		RequestBody: []byte(`{"ItemId":"item-1","SessionId":"session-1","PlaySessionId":"play-session-1"}`),
		OccurredAt:  base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(start) error = %v", err)
	}

	input.RequestURL = "/emby/Sessions/Playing/Stopped"
	input.RequestBody = []byte(`{"ItemId":"item-1","SessionId":"session-1","PlaySessionId":"play-session-1"}`)
	input.OccurredAt = base + int64(30*time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(stopped) error = %v", err)
	}

	input.RequestURL = "/emby/Sessions/Playing"
	input.RequestBody = []byte(`{"ItemId":"item-2","SessionId":"session-2","PlaySessionId":"play-session-2"}`)
	input.OccurredAt = base + int64(31*time.Minute/time.Millisecond)
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(next) error = %v", err)
	}

	var plays, sessions int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "stopped-client").Scan(&plays, &sessions); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 2 || sessions != 1 {
		t.Fatalf("play_stats = plays %d sessions %d; want 2, 1", plays, sessions)
	}
}

func TestLogPlaybackTracksEffectiveDuration(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	base := time.Date(2026, 7, 12, 9, 0, 0, 0, localtime.Location()).UnixMilli()

	logEvent := func(path string, at, positionTicks int64, paused bool) {
		t.Helper()
		input := PlaybackInput{
			Node:       Node{Name: "alpha"},
			RequestIP:  "127.0.0.1",
			Headers:    http.Header{"User-Agent": {"duration-client"}},
			Status:     http.StatusNoContent,
			IsPlayback: true,
			Mode:       "proxy",
			Method:     http.MethodPost,
			RequestURL: path,
			RequestBody: []byte(fmt.Sprintf(
				`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":%d,"IsPaused":%t}`,
				positionTicks,
				paused,
			)),
			OccurredAt: at,
		}
		if err := store.LogPlayback(ctx, input); err != nil {
			t.Fatalf("LogPlayback(%s) error = %v", path, err)
		}
	}

	logEvent("/emby/Sessions/Playing", base, 0, false)
	logEvent("/emby/Sessions/Playing/Progress", base+30_000, 300_000_000, true)
	logEvent("/emby/Sessions/Playing/Progress", base+35_000, 300_000_000, true)
	logEvent("/emby/Sessions/Playing/Progress", base+36_000, 300_000_000, false)
	logEvent("/emby/Sessions/Playing/Stopped", base+46_000, 400_000_000, false)

	var playbackMillis int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(playback_ms), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "duration-client").Scan(&playbackMillis); err != nil {
		t.Fatalf("query play_stats playback duration error = %v", err)
	}
	if playbackMillis != 40_000 {
		t.Fatalf("playback_ms = %d, want 40000", playbackMillis)
	}

	var bucketMillis int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(playback_ms), 0)
		FROM play_buckets
		WHERE node = ? AND client = ?
	`, "alpha", "duration-client").Scan(&bucketMillis); err != nil {
		t.Fatalf("query play_buckets playback duration error = %v", err)
	}
	if bucketMillis != playbackMillis {
		t.Fatalf("play_buckets playback_ms = %d, want %d", bucketMillis, playbackMillis)
	}

	var activeStates, closed int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(closed), 0) FROM playback_states`).Scan(&activeStates, &closed); err != nil {
		t.Fatalf("query playback_states error = %v", err)
	}
	if activeStates != 1 || closed != 1 {
		t.Fatalf("playback state = count %d closed %d, want 1 and 1 after stopped", activeStates, closed)
	}
}

func TestAddPlaybackDurationAggregatesDailyWrites(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	if _, err := store.db.ExecContext(ctx, `
		CREATE TABLE play_stats_write_audit (kind TEXT NOT NULL);
		CREATE TRIGGER audit_play_stats_insert AFTER INSERT ON play_stats BEGIN
			INSERT INTO play_stats_write_audit (kind) VALUES ('insert');
		END;
		CREATE TRIGGER audit_play_stats_update AFTER UPDATE OF playback_ms ON play_stats BEGIN
			INSERT INTO play_stats_write_audit (kind) VALUES ('update');
		END;
	`); err != nil {
		t.Fatalf("create play_stats audit triggers error = %v", err)
	}

	start := time.Date(2026, 7, 12, 12, 0, 50, 0, localtime.Location()).UnixMilli()
	end := start + 30_000
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx() error = %v", err)
	}
	if err := addPlaybackDuration(ctx, tx, start, end, "alpha", "aggregate-client", "proxy"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("addPlaybackDuration() error = %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	var dailyWrites, dailyMillis, activityAt int64
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM play_stats_write_audit`).Scan(&dailyWrites); err != nil {
		t.Fatalf("query play_stats audit error = %v", err)
	}
	if err := store.db.QueryRowContext(ctx, `
		SELECT playback_ms, updated_at FROM play_stats
		WHERE day = ? AND node = ? AND client = ?
	`, "2026-07-12", "alpha", "aggregate-client").Scan(&dailyMillis, &activityAt); err != nil {
		t.Fatalf("query aggregated play_stats error = %v", err)
	}
	var bucketRows, bucketMillis int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(playback_ms), 0) FROM play_buckets
		WHERE node = ? AND client = ?
	`, "alpha", "aggregate-client").Scan(&bucketRows, &bucketMillis); err != nil {
		t.Fatalf("query split play_buckets error = %v", err)
	}
	if dailyWrites != 1 || dailyMillis != 30_000 || activityAt != end {
		t.Fatalf("daily writes = %d playback_ms = %d updated_at = %d; want 1, 30000, %d", dailyWrites, dailyMillis, activityAt, end)
	}
	if bucketRows != 2 || bucketMillis != 30_000 {
		t.Fatalf("bucket rows = %d playback_ms = %d; want 2 and 30000", bucketRows, bucketMillis)
	}
}

func TestLogPlaybackDurationUsesConservativeGapRules(t *testing.T) {
	tests := []struct {
		name           string
		startPosition  int64
		startPaused    bool
		progressOffset int64
		progressPos    int64
		progressPaused bool
		wantMillis     int64
	}{
		{name: "normal heartbeat", progressOffset: 30_000, progressPos: 300_000_000, wantMillis: 30_000},
		{name: "unchanged position", progressOffset: 30_000, progressPos: 0, wantMillis: 0},
		{name: "previously paused", startPaused: true, progressOffset: 30_000, progressPos: 300_000_000, wantMillis: 0},
		{name: "forty second boundary", progressOffset: 40_000, progressPos: 400_000_000, wantMillis: 40_000},
		{name: "gap over forty seconds", progressOffset: 40_001, progressPos: 400_010_000, wantMillis: 0},
		{name: "rewind while playing", startPosition: 300_000_000, progressOffset: 30_000, progressPos: 200_000_000, wantMillis: 30_000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			store := newStatsTestStore(t)
			base := time.Date(2026, 7, 12, 10, 0, 0, 0, localtime.Location()).UnixMilli()
			input := PlaybackInput{
				Node:       Node{Name: "alpha"},
				RequestIP:  "127.0.0.1",
				Headers:    http.Header{"User-Agent": {"gap-client"}},
				Status:     http.StatusNoContent,
				IsPlayback: true,
				Mode:       "proxy",
				Method:     http.MethodPost,
				RequestURL: "/emby/Sessions/Playing",
				RequestBody: []byte(fmt.Sprintf(
					`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":%d,"IsPaused":%t}`,
					tt.startPosition,
					tt.startPaused,
				)),
				OccurredAt: base,
			}
			if err := store.LogPlayback(ctx, input); err != nil {
				t.Fatalf("LogPlayback(start) error = %v", err)
			}

			input.RequestURL = "/emby/Sessions/Playing/Progress"
			input.RequestBody = []byte(fmt.Sprintf(
				`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":%d,"IsPaused":%t}`,
				tt.progressPos,
				tt.progressPaused,
			))
			input.OccurredAt = base + tt.progressOffset
			if err := store.LogPlayback(ctx, input); err != nil {
				t.Fatalf("LogPlayback(progress) error = %v", err)
			}

			var got int64
			if err := store.db.QueryRowContext(ctx, `
				SELECT COALESCE(SUM(playback_ms), 0) FROM play_stats
				WHERE node = ? AND client = ?
			`, "alpha", "gap-client").Scan(&got); err != nil {
				t.Fatalf("query playback_ms error = %v", err)
			}
			if got != tt.wantMillis {
				t.Fatalf("playback_ms = %d, want %d", got, tt.wantMillis)
			}
		})
	}
}

func TestLogPlaybackDurationResumesAfterLongGap(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	base := time.Date(2026, 7, 12, 11, 0, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:        Node{Name: "alpha"},
		RequestIP:   "127.0.0.1",
		Headers:     http.Header{"User-Agent": {"resume-duration-client"}},
		Status:      http.StatusNoContent,
		IsPlayback:  true,
		Mode:        "proxy",
		Method:      http.MethodPost,
		RequestURL:  "/emby/Sessions/Playing",
		RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`),
		OccurredAt:  base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(start) error = %v", err)
	}

	input.RequestURL = "/emby/Sessions/Playing/Progress"
	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":410000000,"IsPaused":false}`)
	input.OccurredAt = base + 41_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(long gap) error = %v", err)
	}

	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":710000000,"IsPaused":false}`)
	input.OccurredAt = base + 71_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(next heartbeat) error = %v", err)
	}

	var got int64
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(playback_ms), 0) FROM play_stats`).Scan(&got); err != nil {
		t.Fatalf("query playback_ms error = %v", err)
	}
	if got != 30_000 {
		t.Fatalf("playback_ms = %d, want 30000", got)
	}
}

func TestLogPlaybackDurationIgnoresOutOfOrderEvents(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	base := time.Date(2026, 7, 12, 12, 0, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:        Node{Name: "alpha"},
		RequestIP:   "127.0.0.1",
		Headers:     http.Header{"User-Agent": {"ordered-client"}},
		Status:      http.StatusNoContent,
		IsPlayback:  true,
		Mode:        "proxy",
		Method:      http.MethodPost,
		RequestURL:  "/emby/Sessions/Playing",
		RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`),
		OccurredAt:  base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(start) error = %v", err)
	}

	input.RequestURL = "/emby/Sessions/Playing/Progress"
	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":300000000,"IsPaused":false}`)
	input.OccurredAt = base + 30_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(first progress) error = %v", err)
	}

	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":200000000,"IsPaused":true}`)
	input.OccurredAt = base + 20_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(stale progress) error = %v", err)
	}

	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":600000000,"IsPaused":false}`)
	input.OccurredAt = base + 60_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(second progress) error = %v", err)
	}

	var got int64
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(playback_ms), 0) FROM play_stats`).Scan(&got); err != nil {
		t.Fatalf("query playback_ms error = %v", err)
	}
	if got != 60_000 {
		t.Fatalf("playback_ms = %d, want 60000", got)
	}
}

func TestLogPlaybackStateOnlyPreservesRequestOrderAcrossResponseLogs(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	base := time.Date(2026, 7, 12, 12, 30, 0, 0, localtime.Location()).UnixMilli()
	inputs := []PlaybackInput{
		{
			RequestURL:  "/emby/Sessions/Playing",
			RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`),
			OccurredAt:  base,
		},
		{
			RequestURL:  "/emby/Sessions/Playing/Progress",
			RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":300000000,"IsPaused":false}`),
			OccurredAt:  base + 30_000,
		},
		{
			RequestURL:  "/emby/Sessions/Playing/Progress",
			RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":600000000,"IsPaused":false}`),
			OccurredAt:  base + 60_000,
		},
	}
	for idx := range inputs {
		inputs[idx].Node = Node{Name: "alpha"}
		inputs[idx].RequestIP = "127.0.0.1"
		inputs[idx].Headers = http.Header{"User-Agent": {"request-order-client"}}
		inputs[idx].Status = http.StatusNoContent
		inputs[idx].IsPlayback = true
		inputs[idx].Mode = "proxy"
		inputs[idx].Method = http.MethodPost
		inputs[idx].PlaybackStateOnly = true
		if err := store.LogPlayback(ctx, inputs[idx]); err != nil {
			t.Fatalf("LogPlayback(state %d) error = %v", idx, err)
		}
	}

	for idx := len(inputs) - 1; idx >= 0; idx-- {
		responseInput := inputs[idx]
		responseInput.PlaybackStateOnly = false
		if err := store.LogPlayback(ctx, responseInput); err != nil {
			t.Fatalf("LogPlayback(response %d) error = %v", idx, err)
		}
	}

	var got int64
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(playback_ms), 0) FROM play_stats`).Scan(&got); err != nil {
		t.Fatalf("query playback_ms error = %v", err)
	}
	if got != 60_000 {
		t.Fatalf("playback_ms = %d, want 60000", got)
	}
}

func TestLogPlaybackStoppedTombstoneRejectsLateProgress(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	base := time.Date(2026, 7, 12, 13, 0, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:        Node{Name: "alpha"},
		RequestIP:   "127.0.0.1",
		Headers:     http.Header{"User-Agent": {"closed-client"}},
		Status:      http.StatusNoContent,
		IsPlayback:  true,
		Mode:        "proxy",
		Method:      http.MethodPost,
		RequestURL:  "/emby/Sessions/Playing",
		RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`),
		OccurredAt:  base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(start) error = %v", err)
	}
	input.RequestURL = "/emby/Sessions/Playing/Progress"
	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":300000000,"IsPaused":false}`)
	input.OccurredAt = base + 30_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(progress) error = %v", err)
	}
	input.RequestURL = "/emby/Sessions/Playing/Stopped"
	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":600000000,"IsPaused":false}`)
	input.OccurredAt = base + 60_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(stopped) error = %v", err)
	}

	for _, event := range []struct {
		at       int64
		position int64
	}{
		{at: base + 45_000, position: 450_000_000},
		{at: base + 90_000, position: 900_000_000},
	} {
		input.RequestURL = "/emby/Sessions/Playing/Progress"
		input.RequestBody = []byte(fmt.Sprintf(
			`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":%d,"IsPaused":false}`,
			event.position,
		))
		input.OccurredAt = event.at
		if err := store.LogPlayback(ctx, input); err != nil {
			t.Fatalf("LogPlayback(late progress) error = %v", err)
		}
	}

	var playbackMillis, lastEventTS int64
	var closed int
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(playback_ms), 0) FROM play_stats`).Scan(&playbackMillis); err != nil {
		t.Fatalf("query playback_ms error = %v", err)
	}
	if err := store.db.QueryRowContext(ctx, `
		SELECT last_event_ts, closed FROM playback_states
	`).Scan(&lastEventTS, &closed); err != nil {
		t.Fatalf("query playback tombstone error = %v", err)
	}
	if playbackMillis != 60_000 || lastEventTS != base+60_000 || closed != 1 {
		t.Fatalf("closed playback = duration %d last %d closed %d; want 60000, %d, 1", playbackMillis, lastEventTS, closed, base+60_000)
	}
}

func TestLogPlaybackStoppedAtSameTimestampClosesState(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	base := time.Date(2026, 7, 12, 14, 0, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:        Node{Name: "alpha"},
		RequestIP:   "127.0.0.1",
		Headers:     http.Header{"User-Agent": {"same-time-client"}},
		Status:      http.StatusNoContent,
		IsPlayback:  true,
		Mode:        "proxy",
		Method:      http.MethodPost,
		RequestURL:  "/emby/Sessions/Playing",
		RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`),
		OccurredAt:  base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(start) error = %v", err)
	}
	input.RequestURL = "/emby/Sessions/Playing/Stopped"
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(stopped) error = %v", err)
	}

	var closed int
	if err := store.db.QueryRowContext(ctx, `SELECT closed FROM playback_states`).Scan(&closed); err != nil {
		t.Fatalf("query playback state error = %v", err)
	}
	if closed != 1 {
		t.Fatalf("closed = %d, want 1", closed)
	}
}

func TestLogPlaybackDurationSplitsAcrossBeijingDays(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	base := time.Date(2026, 7, 11, 23, 59, 50, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:        Node{Name: "alpha"},
		RequestIP:   "127.0.0.1",
		Headers:     http.Header{"User-Agent": {"midnight-client"}},
		Status:      http.StatusNoContent,
		IsPlayback:  true,
		Mode:        "proxy",
		Method:      http.MethodPost,
		RequestURL:  "/emby/Sessions/Playing",
		RequestBody: []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":0,"IsPaused":false}`),
		OccurredAt:  base,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(start) error = %v", err)
	}
	input.RequestURL = "/emby/Sessions/Playing/Stopped"
	input.RequestBody = []byte(`{"ItemId":"item-1","PlaySessionId":"play-session-1","PositionTicks":200000000,"IsPaused":false}`)
	input.OccurredAt = base + 20_000
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback(stopped) error = %v", err)
	}

	for _, tt := range []struct {
		day            string
		wantActivityAt int64
	}{
		{day: "2026-07-11", wantActivityAt: base + 9_999},
		{day: "2026-07-12", wantActivityAt: base + 20_000},
	} {
		var got, activityAt int64
		if err := store.db.QueryRowContext(ctx, `
			SELECT playback_ms, updated_at FROM play_stats
			WHERE day = ? AND node = ? AND client = ?
		`, tt.day, "alpha", "midnight-client").Scan(&got, &activityAt); err != nil {
			t.Fatalf("query %s playback_ms error = %v", tt.day, err)
		}
		if got != 10_000 {
			t.Fatalf("%s playback_ms = %d, want 10000", tt.day, got)
		}
		if activityAt != tt.wantActivityAt {
			t.Fatalf("%s updated_at = %d, want %d", tt.day, activityAt, tt.wantActivityAt)
		}
	}
}

func TestLogPlaybackDedupsSessionWithoutDeviceOrSessionID(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	base := time.Date(2026, 6, 9, 15, 45, 0, 0, localtime.Location()).UnixMilli()
	input := PlaybackInput{
		Node:       Node{Name: "alpha"},
		RequestIP:  "198.51.100.42",
		Headers:    http.Header{"User-Agent": {"test-client"}},
		Status:     http.StatusNoContent,
		IsPlayback: true,
		Mode:       "proxy",
		Method:     http.MethodPost,
		RequestURL: "/emby/Sessions/Playing",
		RequestBody: []byte(`{
			"ItemId": "item-a"
		}`),
		OccurredAt: base,
	}
	for idx := 0; idx < 9; idx++ {
		input.OccurredAt = base + int64(idx)*int64(time.Second/time.Millisecond)
		if err := store.LogPlayback(ctx, input); err != nil {
			t.Fatalf("LogPlayback(%d) error = %v", idx, err)
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
		t.Fatalf("play_stats = plays %d sessions %d; want 1, 1", plays, sessions)
	}
}

func TestLogPlaybackDoesNotCountHeadAsPlay(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

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
	if plays != 0 || sessions != 0 || bytes != 0 {
		t.Fatalf("play_stats = plays %d sessions %d bytes %d; want 0, 0, 0", plays, sessions, bytes)
	}
}

func TestLogPlaybackDoesNotCountPlaybackInfoAsPlayOrTraffic(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	input := PlaybackInput{
		Node:       Node{Name: "alpha"},
		RequestIP:  "127.0.0.1",
		Headers:    http.Header{"User-Agent": {"info-client"}},
		Status:     http.StatusOK,
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/Items/1/PlaybackInfo",
		Method:     http.MethodGet,
	}
	if err := store.LogPlayback(ctx, input); err != nil {
		t.Fatalf("LogPlayback() error = %v", err)
	}
	traffic := input
	traffic.TrafficOnly = true
	traffic.InboundBytes = 256
	traffic.OutboundBytes = 512
	if err := store.LogPlaybackTraffic(ctx, traffic); err != nil {
		t.Fatalf("LogPlaybackTraffic() error = %v", err)
	}

	var plays, sessions, bytes int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(sessions), 0), COALESCE(SUM(bytes), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "info-client").Scan(&plays, &sessions, &bytes); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 0 || sessions != 0 || bytes != 0 {
		t.Fatalf("play_stats = plays %d sessions %d bytes %d; want 0, 0, 0", plays, sessions, bytes)
	}
}

func TestLogPlaybackTrafficCountsReadAndWriteBytes(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

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

	var plays, bytes, inboundBytes, outboundBytes int64
	if err := store.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0), COALESCE(SUM(bytes), 0), COALESCE(SUM(inbound_bytes), 0), COALESCE(SUM(outbound_bytes), 0)
		FROM play_stats
		WHERE node = ? AND client = ?
	`, "alpha", "range-client").Scan(&plays, &bytes, &inboundBytes, &outboundBytes); err != nil {
		t.Fatalf("query play_stats error = %v", err)
	}
	if plays != 0 || bytes != 1280 || inboundBytes != 768 || outboundBytes != 512 {
		t.Fatalf("play_stats plays = %d bytes = %d inbound = %d outbound = %d; want 0, 1280, 768, 512", plays, bytes, inboundBytes, outboundBytes)
	}
}

func TestLogPlaybackAsyncDoesNotWaitForDatabase(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx() error = %v", err)
	}

	input := PlaybackInput{
		Node:       Node{Name: "async"},
		RequestIP:  "127.0.0.1",
		Headers:    http.Header{"User-Agent": {"async-client"}},
		Status:     http.StatusNoContent,
		RespHeader: http.Header{"Content-Length": {"2048"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/Sessions/Playing",
		Method:     http.MethodPost,
		RequestBody: []byte(`{
			"ItemId": "2",
			"SessionId": "session-async",
			"PlaySessionId": "play-session-async"
		}`),
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
	store := newStatsTestStore(t)

	occurredAt := time.Date(2000, 1, 2, 16, 0, 1, 0, time.UTC).UnixMilli()
	input := PlaybackInput{
		Node:       Node{Name: "occurred"},
		RequestIP:  "127.0.0.1",
		Headers:    http.Header{"User-Agent": {"time-client"}},
		Status:     http.StatusNoContent,
		RespHeader: http.Header{"Content-Length": {"4096"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/Sessions/Playing",
		Method:     http.MethodPost,
		RequestBody: []byte(`{
			"ItemId": "3",
			"SessionId": "session-occurred",
			"PlaySessionId": "play-session-occurred"
		}`),
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
	store := newStatsTestStore(t)

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

func TestGetPlayStatsReturnsLastActivity(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	now := localtime.Now()
	lastActivityAt := now.Add(-90 * time.Second).UnixMilli()

	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO play_stats (day, node, client, plays, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at)
		VALUES (?, ?, ?, ?, 0, 0, 0, ?, 0, ?)
	`, now.Format("2006-01-02"), "alpha", "client", 2, 1, lastActivityAt); err != nil {
		t.Fatalf("insert play stat error = %v", err)
	}

	stats, err := store.GetPlayStats(ctx, 1)
	if err != nil {
		t.Fatalf("GetPlayStats() error = %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("GetPlayStats() len = %d, want 1: %+v", len(stats), stats)
	}
	if stats[0].LastActivityAt != lastActivityAt {
		t.Fatalf("LastActivityAt = %d, want %d", stats[0].LastActivityAt, lastActivityAt)
	}
	wantText := localtime.FormatUnixMilli(lastActivityAt, "2006-01-02 15:04:05")
	if stats[0].LastActivity != wantText {
		t.Fatalf("LastActivity = %q, want %q", stats[0].LastActivity, wantText)
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
		CREATE TABLE play_buckets (
			bucket_start INTEGER NOT NULL,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			mode TEXT NOT NULL,
			plays INTEGER DEFAULT 0,
			bytes INTEGER DEFAULT 0,
			inbound_bytes INTEGER DEFAULT 0,
			outbound_bytes INTEGER DEFAULT 0,
			sessions INTEGER DEFAULT 0,
			errors INTEGER DEFAULT 0,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(bucket_start, node, client, mode)
		);
		CREATE TABLE playback_states (
			k TEXT PRIMARY KEY,
			node TEXT NOT NULL,
			client TEXT NOT NULL,
			mode TEXT NOT NULL,
			item_key TEXT NOT NULL,
			last_event_ts INTEGER NOT NULL,
			last_position_ticks INTEGER NOT NULL DEFAULT 0,
			has_position INTEGER NOT NULL DEFAULT 0,
			is_paused INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL
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
	if stats[0].PlaybackMillis != 0 || stats[0].Bytes != 0 || stats[0].OutboundBytes != 0 || stats[0].InboundBytes != 0 {
		t.Fatalf("migrated stats = playback %d bytes %d inbound %d outbound %d; want 0, 0, 0, 0", stats[0].PlaybackMillis, stats[0].Bytes, stats[0].InboundBytes, stats[0].OutboundBytes)
	}
	for _, table := range []string{"play_stats", "play_buckets"} {
		columns, err := store.tableColumns(ctx, table)
		if err != nil {
			t.Fatalf("tableColumns(%s) error = %v", table, err)
		}
		if !columns["playback_ms"] {
			t.Fatalf("%s missing playback_ms after migration", table)
		}
	}
	stateColumns, err := store.tableColumns(ctx, "playback_states")
	if err != nil {
		t.Fatalf("tableColumns(playback_states) error = %v", err)
	}
	if !stateColumns["closed"] {
		t.Fatal("playback_states missing closed after migration")
	}
}

func newStatsTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func TestGetRangeStatsUsesMinuteBucketsAndPrune(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)

	now := time.Now().UnixMilli()
	t1 := playbackBucketStart(now-12*60*60*1000) + 10*1000
	t2 := t1 + 20*1000
	tOld := playbackBucketStart(now - 4*24*60*60*1000)

	// 1. Log a play at t1
	input1 := PlaybackInput{
		Node:       Node{Name: "node1"},
		RequestIP:  "127.0.0.1",
		Headers:    http.Header{"User-Agent": {"client1"}},
		Status:     http.StatusNoContent,
		RespHeader: http.Header{"Content-Length": {"1024"}},
		IsPlayback: true,
		Mode:       "proxy",
		RequestURL: "/emby/Sessions/Playing",
		Method:     http.MethodPost,
		RequestBody: []byte(`{
			"ItemId": "1",
			"SessionId": "session-1",
			"PlaySessionId": "play-session-1"
		}`),
		OccurredAt: t1,
	}
	if err := store.LogPlayback(ctx, input1); err != nil {
		t.Fatalf("LogPlayback at t1 failed: %v", err)
	}

	// 2. Log a traffic update in the same minute bucket.
	input2 := PlaybackInput{
		Node:          Node{Name: "node1"},
		RequestIP:     "127.0.0.1",
		Headers:       http.Header{"User-Agent": {"client1"}},
		Status:        http.StatusOK,
		IsPlayback:    true,
		Mode:          "proxy",
		RequestURL:    "/emby/videos/1/stream",
		Method:        http.MethodGet,
		OccurredAt:    t2,
		TrafficOnly:   true,
		InboundBytes:  500,
		OutboundBytes: 700,
	}
	if err := store.LogPlaybackTraffic(ctx, input2); err != nil {
		t.Fatalf("LogPlaybackTraffic at t2 failed: %v", err)
	}

	// 3. Log a direct play in the same minute bucket.
	inputDirect := input1
	inputDirect.OccurredAt = t1 + 30*1000
	inputDirect.Mode = "direct"
	inputDirect.RequestBody = []byte(`{
		"ItemId": "2",
		"SessionId": "session-1",
		"PlaySessionId": "play-session-2"
	}`)
	if err := store.LogPlayback(ctx, inputDirect); err != nil {
		t.Fatalf("LogPlayback direct failed: %v", err)
	}

	var proxyBucketRows int
	if err := store.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM play_buckets
		WHERE bucket_start = ? AND node = ? AND client = ? AND mode = ?
	`, playbackBucketStart(t1), "node1", "client1", "proxy").Scan(&proxyBucketRows); err != nil {
		t.Fatalf("query play_buckets error = %v", err)
	}
	if proxyBucketRows != 1 {
		t.Fatalf("proxy bucket rows = %d; want 1", proxyBucketRows)
	}

	// 4. Log an old play at tOld
	inputOld := input1
	inputOld.OccurredAt = tOld
	inputOld.Node.Name = "node-old"
	if err := store.LogPlayback(ctx, inputOld); err != nil {
		t.Fatalf("LogPlayback at tOld failed: %v", err)
	}

	// Verify stats in range [now - 24h, now + 1h)
	stats, proxyPlays, directPlays, err := store.GetRangeStats(ctx, now-24*60*60*1000, now+60*60*1000)
	if err != nil {
		t.Fatalf("GetRangeStats failed: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("expected 1 stat group, got %d: %+v", len(stats), stats)
	}
	if stats[0].Node != "node1" || stats[0].Client != "client1" {
		t.Fatalf("unexpected stat: %+v", stats[0])
	}
	if stats[0].Plays != 2 || stats[0].InboundBytes != 500 || stats[0].OutboundBytes != 700 || stats[0].Sessions != 1 {
		t.Fatalf("unexpected metrics in stat: %+v", stats[0])
	}
	if proxyPlays != 1 || directPlays != 1 {
		t.Fatalf("unexpected proxy/direct plays: proxy=%d, direct=%d", proxyPlays, directPlays)
	}

	// Verify old stat is visible in full range query
	allStats, _, _, err := store.GetRangeStats(ctx, now-50*24*60*60*1000, now+60*60*1000)
	if err != nil {
		t.Fatalf("GetRangeStats for full range failed: %v", err)
	}
	foundOld := false
	for _, s := range allStats {
		if s.Node == "node-old" {
			foundOld = true
			break
		}
	}
	if !foundOld {
		t.Fatalf("old play stat not found in full range query")
	}

	// Prune old buckets (keep last 3 days)
	if err := store.PrunePlayBuckets(ctx, 3); err != nil {
		t.Fatalf("PrunePlayBuckets failed: %v", err)
	}

	// Verify old stat is gone, but new stat remains
	allStatsAfter, _, _, err := store.GetRangeStats(ctx, now-50*24*60*60*1000, now+60*60*1000)
	if err != nil {
		t.Fatalf("GetRangeStats after prune failed: %v", err)
	}
	for _, s := range allStatsAfter {
		if s.Node == "node-old" {
			t.Fatalf("old play stat still exists after prune")
		}
	}
}

func TestPrunePlaybackStatesRemovesOnlyExpiredRows(t *testing.T) {
	ctx := context.Background()
	store := newStatsTestStore(t)
	now := time.Now().UnixMilli()
	for _, row := range []struct {
		key       string
		updatedAt int64
	}{
		{key: "expired", updatedAt: now - int64(25*time.Hour/time.Millisecond)},
		{key: "active", updatedAt: now - int64(time.Hour/time.Millisecond)},
	} {
		if _, err := store.db.ExecContext(ctx, `
			INSERT INTO playback_states (
				k, node, client, mode, item_key, last_event_ts, last_position_ticks, has_position, is_paused, updated_at
			) VALUES (?, 'node', 'client', 'proxy', 'item:1', ?, 0, 1, 0, ?)
		`, row.key, row.updatedAt, row.updatedAt); err != nil {
			t.Fatalf("insert playback state %s error = %v", row.key, err)
		}
	}

	if err := store.PrunePlaybackStates(ctx, 24*time.Hour); err != nil {
		t.Fatalf("PrunePlaybackStates() error = %v", err)
	}
	var keys string
	if err := store.db.QueryRowContext(ctx, `SELECT GROUP_CONCAT(k, ',') FROM playback_states`).Scan(&keys); err != nil {
		t.Fatalf("query playback states error = %v", err)
	}
	if keys != "active" {
		t.Fatalf("remaining playback state keys = %q, want active", keys)
	}
}
