package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/proxy"
	"embyproxy/internal/requestlog"
	"embyproxy/internal/storage"
)

func TestShouldPrintVersion(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "long flag", args: []string{"--version"}, want: true},
		{name: "short flag", args: []string{"-v"}, want: true},
		{name: "command", args: []string{"version"}, want: true},
		{name: "no args", args: nil, want: false},
		{name: "serve arg", args: []string{"serve"}, want: false},
		{name: "extra args", args: []string{"--version", "extra"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPrintVersion(tt.args); got != tt.want {
				t.Fatalf("shouldPrintVersion(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestRequestMiddlewareWritesAccessLogByDefault(t *testing.T) {
	log := logging.New("info", true)
	handler := requestMiddleware(log, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin", nil))

	entries := log.Entries(10)
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if entry.Scope != "access" {
			t.Fatalf("scope = %q, want access", entry.Scope)
		}
	}
	for _, want := range []string{"event=requestStarted", "method=GET", "uri=/admin"} {
		if !strings.Contains(entries[0].Line, want) {
			t.Fatalf("request started log line = %q, want %q", entries[0].Line, want)
		}
	}
	for _, want := range []string{"event=requestFinished", "method=GET", "uri=/admin"} {
		if !strings.Contains(entries[1].Line, want) {
			t.Fatalf("request finished log line = %q, want %q", entries[1].Line, want)
		}
	}
	if startedID, finishedID := logField(t, entries[0].Line, "id"), logField(t, entries[1].Line, "id"); startedID != finishedID {
		t.Fatalf("request id mismatch: started=%q finished=%q", startedID, finishedID)
	}
	if !strings.Contains(entries[1].Line, "totalMs=") {
		t.Fatalf("access log line = %q, want totalMs field", entries[1].Line)
	}
	if strings.Contains(entries[1].Line, " ms=") {
		t.Fatalf("access log line kept generic ms field: %q", entries[1].Line)
	}
}

func logField(t *testing.T, line, key string) string {
	t.Helper()
	prefix := key + "="
	for _, part := range strings.Fields(line) {
		if strings.HasPrefix(part, prefix) {
			return strings.TrimPrefix(part, prefix)
		}
	}
	t.Fatalf("log line = %q, want field %q", line, key)
	return ""
}

func TestRequestMiddlewareWritesBodyTimingAccessFields(t *testing.T) {
	log := logging.New("info", true)
	handler := requestMiddleware(log, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.SetAccessLogField(r.Context(), "responseReadyMs", int64(5))
		proxy.MarkAccessLogResponseBodyStart(r.Context(), time.Now())
		time.Sleep(time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/emby/videos/1/stream.mkv", nil))

	entries := log.Entries(10)
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	if !strings.Contains(entries[0].Line, "event=requestStarted") {
		t.Fatalf("first access log line = %q, want requestStarted", entries[0].Line)
	}
	for _, want := range []string{"totalMs=", "responseReadyMs=5", "bodyMs="} {
		if !strings.Contains(entries[1].Line, want) {
			t.Fatalf("access log line = %q, want %q", entries[1].Line, want)
		}
	}
	for _, old := range []string{" ms=", "targetMs=", "targetHeaderMs="} {
		if strings.Contains(entries[1].Line, old) {
			t.Fatalf("access log line kept old timing field %q: %q", old, entries[1].Line)
		}
	}
}

func TestRequestMiddlewareKeepsClientIPWhenRequestContextIsCanceled(t *testing.T) {
	log := logging.New("info", true)
	store, err := storage.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	cfg := storage.DefaultSystemConfig()
	cfg.TrustProxy = true
	if err := store.KV().Put(context.Background(), "system:config", cfg); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	reqCtx, cancel := context.WithCancel(context.Background())
	handler := requestMiddleware(log, store, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		_, _ = w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/emby/videos/1/original.mkv", nil).WithContext(reqCtx)
	req.RemoteAddr = "172.19.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.42")

	handler.ServeHTTP(httptest.NewRecorder(), req)

	entries := log.Entries(10)
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if !strings.Contains(entry.Line, "ip=203.0.113.42") {
			t.Fatalf("access log line = %q, want forwarded client IP", entry.Line)
		}
		if strings.Contains(entry.Line, "ip=172.19.0.1") {
			t.Fatalf("access log fell back to docker bridge IP: %q", entry.Line)
		}
	}
}

func TestRequestMiddlewareSuppressesMarkedAccessLog(t *testing.T) {
	log := logging.New("info", true)
	handler := requestMiddleware(log, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestlog.SuppressAccessLog(r.Context())
		_, _ = w.Write([]byte("ok"))
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/admin/api", nil))

	if entries := log.Entries(10); len(entries) != 0 {
		t.Fatalf("entries len = %d, want 0: %+v", len(entries), entries)
	}
}

func TestRequestMiddlewareUsesRedactedRequestURI(t *testing.T) {
	log := logging.New("info", true)
	historyPath := filepath.Join(t.TempDir(), "console-logs.jsonl")
	if err := log.EnableHistory(historyPath, logging.DefaultHistoryEntriesFile, 1); err != nil {
		t.Fatalf("EnableHistory() error = %v", err)
	}
	handler := requestMiddleware(log, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestlog.SetRequestURI(r.Context(), "/node/<secret>/emby/Items?X-Emby-Token=<redacted>")
		_, _ = w.Write([]byte("ok"))
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/node/raw-secret/emby/Items?X-Emby-Token=token", nil))

	entries := log.Entries(10)
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if strings.Contains(entry.Line, "raw-secret") || strings.Contains(entry.Line, "token") {
			t.Fatalf("access log leaked sensitive data: %q", entry.Line)
		}
		if !strings.Contains(entry.Line, "/node/<secret>/emby/Items?X-Emby-Token=<redacted>") {
			t.Fatalf("access log line = %q, want redacted URI", entry.Line)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	history, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(history), "raw-secret") || strings.Contains(string(history), "token") {
		t.Fatalf("history log leaked sensitive data: %q", string(history))
	}
}

func TestProxyRequestLogsClientUpstreamAndFinishLifecycle(t *testing.T) {
	log := logging.New("info", true)
	ctx := context.Background()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatalf("storage.New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 0-4/5")
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(upstream.Close)
	if err := store.SaveNode(ctx, "admin", storage.Node{Name: "node", Secret: "raw-secret", Target: upstream.URL}); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	proxyHandler := proxy.New(config.Config{CWD: t.TempDir()}, store, nil, log)
	handler := requestMiddleware(log, store, proxyHandler)
	req := httptest.NewRequest(http.MethodGet, "/node/raw-secret/emby/videos/1/original.mkv?api_key=token", nil)
	req.Header.Set("Range", "bytes=0-")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}
	entries := log.Entries(10)
	if len(entries) != 3 {
		t.Fatalf("entries len = %d, want 3: %+v", len(entries), entries)
	}
	wants := [][]string{
		{"event=requestStarted", "[access]", "node=node", "range=\"bytes=0-\""},
		{"event=upstreamReady", "[proxy]", "node=node", "range=\"bytes=0-\"", "contentRange=\"bytes 0-4/5\""},
		{"event=requestFinished", "[access]", "range=\"bytes=0-\"", "contentRange=\"bytes 0-4/5\""},
	}
	for i, wantParts := range wants {
		for _, want := range wantParts {
			if !strings.Contains(entries[i].Line, want) {
				t.Fatalf("entry %d line = %q, want %q", i, entries[i].Line, want)
			}
		}
		if strings.Contains(entries[i].Line, "raw-secret") || strings.Contains(entries[i].Line, "token") {
			t.Fatalf("entry %d leaked sensitive data: %q", i, entries[i].Line)
		}
	}
}
