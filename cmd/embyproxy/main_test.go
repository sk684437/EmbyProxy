package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"embyproxy/internal/logging"
	"embyproxy/internal/requestlog"
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
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if entries[0].Scope != "access" {
		t.Fatalf("scope = %q, want access", entries[0].Scope)
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
	if len(entries) != 1 {
		t.Fatalf("entries len = %d, want 1", len(entries))
	}
	if strings.Contains(entries[0].Line, "raw-secret") || strings.Contains(entries[0].Line, "token") {
		t.Fatalf("access log leaked sensitive data: %q", entries[0].Line)
	}
	if !strings.Contains(entries[0].Line, "/node/<secret>/emby/Items?X-Emby-Token=<redacted>") {
		t.Fatalf("access log line = %q, want redacted URI", entries[0].Line)
	}
	history, err := os.ReadFile(historyPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(history), "raw-secret") || strings.Contains(string(history), "token") {
		t.Fatalf("history log leaked sensitive data: %q", string(history))
	}
}
