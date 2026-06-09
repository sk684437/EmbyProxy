package logging

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactTextRedactsEmbeddedURLQuerySecrets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		leaks []string
		wants []string
	}{
		{
			name:  "regular URL",
			input: `Get "https://emby.example/emby/Items/1?X-Emby-Token=secret-token&fields=ShareLevel&api_key=secret-key": context canceled`,
			leaks: []string{"secret-token", "secret-key"},
			wants: []string{"X-Emby-Token=<redacted>", "api_key=<redacted>", "fields=ShareLevel"},
		},
		{
			name:  "parentheses in path",
			input: `Get "https://cdn.example/video/Devote%20100%20Days%20(2025)%5Btmdb=306641%5D/S01E03.mkv?auth_key=secret-auth-key": net/http: TLS handshake timeout`,
			leaks: []string{"secret-auth-key"},
			wants: []string{"auth_key=<redacted>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactText(tt.input)
			for _, leak := range tt.leaks {
				if strings.Contains(got, leak) {
					t.Fatalf("RedactText() leaked %q in %q", leak, got)
				}
			}
			for _, want := range tt.wants {
				if !strings.Contains(got, want) {
					t.Fatalf("RedactText() = %q, want to contain %q", got, want)
				}
			}
		})
	}
}

func TestRedactURLRedactsSignedURLQuery(t *testing.T) {
	got := RedactURL("https://cdn.example/video.mkv?sign=secret-sign&signature=secret-signature&design=poster")

	if strings.Contains(got, "secret-sign") || strings.Contains(got, "secret-signature") {
		t.Fatalf("RedactURL() leaked signed URL query values: %q", got)
	}
	for _, want := range []string{"sign=<redacted>", "signature=<redacted>", "design=poster"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RedactURL() = %q, want to contain %q", got, want)
		}
	}
}

func TestFormatValueRedactsEmbeddedURLInErrorMeta(t *testing.T) {
	got := formatValue(`Get "https://emby.example/emby/Items/1?X-Emby-Token=secret-token&fields=ShareLevel": context canceled`)

	if strings.Contains(got, "secret-token") {
		t.Fatalf("formatValue() leaked sensitive query values: %q", got)
	}
	if !strings.Contains(got, "X-Emby-Token=<redacted>") {
		t.Fatalf("formatValue() = %q, want redacted token", got)
	}
}

func TestLoggerEntriesReturnsRedactedConsoleLines(t *testing.T) {
	log := New("debug", true)
	log.Info("proxy", "target headers received", map[string]any{
		"target": "https://emby.example/Items?api_key=secret-key&Fields=Name",
		"status": 200,
	})

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	got := entries[0]
	if got.ID != 1 || got.Level != "info" || got.Scope != "proxy" {
		t.Fatalf("entry metadata = %+v", got)
	}
	if strings.Contains(got.Line, "secret-key") {
		t.Fatalf("entry line leaked sensitive query value: %q", got.Line)
	}
	for _, want := range []string{"INFO", "[200]", "[proxy]", "api_key=<redacted>", "Fields=Name"} {
		if !strings.Contains(got.Line, want) {
			t.Fatalf("entry line = %q, want to contain %q", got.Line, want)
		}
	}
}

func TestFormatMetaUsesSemanticFieldOrder(t *testing.T) {
	got := formatMeta(map[string]any{
		"bodyCopyError":   "broken pipe",
		"target":          "https://cdn.example",
		"upstreamPool":    "playbackStream",
		"event":           "requestFinished",
		"totalMs":         24,
		"range":           "bytes=1024-",
		"nodeTarget":      "https://upstream.example",
		"uri":             "/node/<secret>/emby/videos/1/original.mkv",
		"method":          "GET",
		"id":              "req-1",
		"ip":              "127.0.0.1",
		"contentRange":    "bytes 1024-2047/4096",
		"bytes":           1024,
		"responseReadyMs": 8,
		"bodyMs":          16,
	})

	wantOrder := []string{
		"event=requestFinished",
		"id=req-1",
		"method=GET",
		"uri=",
		"ip=127.0.0.1",
		"nodeTarget=https://upstream.example",
		"target=https://cdn.example",
		"upstreamPool=playbackStream",
		"range=\"bytes=1024-\"",
		"contentRange=\"bytes 1024-2047/4096\"",
		" bytes=1024 ",
		"responseReadyMs=8",
		"bodyMs=16",
		"totalMs=24",
		"bodyCopyError=\"broken pipe\"",
	}
	assertLineOrder(t, got, wantOrder)
}

func TestLoggerLineSuppressesMessageWhenEventIsPresent(t *testing.T) {
	log := New("debug", true)
	log.Info("access", "request finished", map[string]any{"event": "requestFinished", "id": "req-1"})

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if strings.Contains(entries[0].Line, "request finished") {
		t.Fatalf("line kept message despite event field: %q", entries[0].Line)
	}
	if !strings.Contains(entries[0].Line, "event=requestFinished id=req-1") {
		t.Fatalf("line = %q, want event and id fields", entries[0].Line)
	}
	if entries[0].Message != "request finished" {
		t.Fatalf("message = %q, want preserved message", entries[0].Message)
	}
}

func TestLoggerEntriesHonorsLimit(t *testing.T) {
	log := New("debug", true)
	log.Info("test", "one", nil)
	log.Warn("test", "two", nil)
	log.Error("test", "three", nil)

	entries := log.Entries(2)
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	if entries[0].Message != "two" || entries[1].Message != "three" {
		t.Fatalf("entries = %+v, want last two messages", entries)
	}
}

func TestLoggerHistoryPagination(t *testing.T) {
	tests := []struct {
		name       string
		maxFiles   int
		wantOldest string
	}{
		{name: "history pages older entries", maxFiles: 3, wantOldest: "line-1"},
		{name: "latest page uses memory buffer when history rotated away", maxFiles: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := New("debug", true)
			if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, tt.maxFiles); err != nil {
				t.Fatalf("EnableHistory() error = %v", err)
			}
			t.Cleanup(func() { _ = log.Close() })
			for i := 1; i <= 5; i++ {
				log.Info("test", fmt.Sprintf("line-%d", i), nil)
			}

			latest := log.Page(2, 0)
			if !latest.History || !latest.HasOlder {
				t.Fatalf("latest page metadata = %+v", latest)
			}
			if messages(latest.Entries) != "line-4,line-5" {
				t.Fatalf("latest messages = %q", messages(latest.Entries))
			}

			older := log.Page(2, latest.Entries[0].ID)
			if messages(older.Entries) != "line-2,line-3" {
				t.Fatalf("older messages = %q", messages(older.Entries))
			}
			if tt.wantOldest == "" {
				return
			}
			if !older.HasOlder {
				t.Fatalf("older page metadata = %+v", older)
			}

			oldest := log.Page(2, older.Entries[0].ID)
			if oldest.HasOlder {
				t.Fatalf("oldest page metadata = %+v", oldest)
			}
			if messages(oldest.Entries) != tt.wantOldest {
				t.Fatalf("oldest messages = %q", messages(oldest.Entries))
			}
		})
	}
}

func TestLoggerEnableHistoryClosesPreviousHistory(t *testing.T) {
	log := New("debug", true)
	historyPath := filepath.Join(t.TempDir(), "console-logs.jsonl")
	t.Cleanup(func() { _ = log.Close() })
	if err := log.EnableHistory(historyPath, 10, 2); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	log.Info("test", "before", nil)

	if err := log.EnableHistory(historyPath, 10, 2); err != nil {
		t.Fatalf("second EnableHistory() error = %v", err)
	}
	log.Info("test", "after", nil)
}

func TestLoggerClearRemovesBufferedAndHistoryEntries(t *testing.T) {
	log := New("debug", true)
	if err := log.EnableHistory(filepath.Join(t.TempDir(), "console-logs.jsonl"), 2, 3); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for i := 1; i <= 3; i++ {
		log.Info("test", fmt.Sprintf("before-%d", i), nil)
	}
	if page := log.Page(10, 0); messages(page.Entries) != "before-1,before-2,before-3" {
		t.Fatalf("entries before clear = %q", messages(page.Entries))
	}

	if err := log.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	cleared := log.Page(10, 0)
	if len(cleared.Entries) != 0 || cleared.HasOlder != false || !cleared.History {
		t.Fatalf("page after clear = %+v", cleared)
	}
	log.Info("test", "after", nil)
	latest := log.Page(10, 0)
	if messages(latest.Entries) != "after" {
		t.Fatalf("entries after clear = %q", messages(latest.Entries))
	}
	if latest.Entries[0].ID != 1 {
		t.Fatalf("first entry ID after clear = %d, want 1", latest.Entries[0].ID)
	}
}

func messages(entries []LogEntry) string {
	values := make([]string, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry.Message)
	}
	return strings.Join(values, ",")
}

func assertLineOrder(t *testing.T, line string, fragments []string) {
	t.Helper()
	last := -1
	for _, fragment := range fragments {
		idx := strings.Index(line, fragment)
		if idx < 0 {
			t.Fatalf("line = %q, want fragment %q", line, fragment)
		}
		if idx <= last {
			t.Fatalf("line = %q, fragment %q appeared out of order", line, fragment)
		}
		last = idx
	}
}
