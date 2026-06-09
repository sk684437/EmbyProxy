package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"embyproxy/internal/auth"
	"embyproxy/internal/buildinfo"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/requestlog"
	"embyproxy/internal/storage"
)

func TestServeAdminValidatesTokenConfig(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		wantStatus int
		wantBody   []string
	}{
		{name: "missing admin token", wantStatus: http.StatusInternalServerError, wantBody: []string{auth.AdminTokenNotConfigured}},
		{name: "configured admin token", token: "strong-random-admin-token", wantStatus: http.StatusOK, wantBody: []string{`id="loginWrap"`, `id="appVersion"`}},
		{name: "default admin token", token: "change-me-please", wantStatus: http.StatusInternalServerError, wantBody: []string{auth.AdminTokenDefault}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{AdminToken: tt.token}
			handler := New(cfg, nil, auth.NewChecker(cfg, nil), nil, nil, nil)
			req := httptest.NewRequest(http.MethodGet, "/admin", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			for _, want := range tt.wantBody {
				if !strings.Contains(rec.Body.String(), want) {
					t.Fatalf("body = %q, want to contain %q", rec.Body.String(), want)
				}
			}
		})
	}
}

func TestListIncludesBuildInfo(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	oldVersion, oldCommit, oldBuiltAt := buildinfo.Version, buildinfo.Commit, buildinfo.BuiltAt
	buildinfo.Version, buildinfo.Commit, buildinfo.BuiltAt = "v-test", "abc1234", "2026-05-31T00:00:00Z"
	defer func() {
		buildinfo.Version, buildinfo.Commit, buildinfo.BuiltAt = oldVersion, oldCommit, oldBuiltAt
	}()

	res := handler.list(ctx, "admin")
	got, ok := res["build"].(buildinfo.Info)
	if !ok {
		t.Fatalf("build info type = %T, want buildinfo.Info", res["build"])
	}
	if got.Version != "v-test" || got.Commit != "abc1234" || got.BuiltAt != "2026-05-31T00:00:00Z" {
		t.Fatalf("build info = %+v", got)
	}
}

func TestDispatchLogsListReturnsBufferedLogs(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	handler.log.Configure("info", false)
	handler.log.Info("admin", "config saved", map[string]any{"status": "ok"})
	res, status := handler.dispatch(ctx, "admin", "logs.list", map[string]any{"limit": 10})

	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch logs.list status=%d res=%+v", status, res)
	}
	logs, ok := res["logs"].([]logging.LogEntry)
	if !ok {
		t.Fatalf("logs type = %T, want []logging.LogEntry", res["logs"])
	}
	if len(logs) != 1 {
		t.Fatalf("logs len = %d, want 1", len(logs))
	}
	if logs[0].Level != "info" || logs[0].Scope != "admin" || !strings.Contains(logs[0].Line, "config saved") {
		t.Fatalf("log entry = %+v", logs[0])
	}
}

func TestDispatchLogsClearRemovesBufferedLogs(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	handler.log.Configure("info", false)
	handler.log.Info("admin", "before clear", nil)
	res, status := handler.dispatch(ctx, "admin", "logs.clear", map[string]any{})

	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch logs.clear status=%d res=%+v", status, res)
	}
	logs, ok := res["logs"].([]logging.LogEntry)
	if !ok {
		t.Fatalf("logs type = %T, want []logging.LogEntry", res["logs"])
	}
	if len(logs) != 0 {
		t.Fatalf("logs len after clear = %d, want 0", len(logs))
	}

	handler.log.Info("admin", "after clear", nil)
	res, status = handler.dispatch(ctx, "admin", "logs.list", map[string]any{"limit": 10})
	if status != http.StatusOK || res["ok"] != true {
		t.Fatalf("dispatch logs.list status=%d res=%+v", status, res)
	}
	logs = res["logs"].([]logging.LogEntry)
	if len(logs) != 1 || !strings.Contains(logs[0].Line, "after clear") {
		t.Fatalf("logs after new write = %+v", logs)
	}
}

func TestHandleAPISuppressesLogReadActionsAccessLogAndTrafficCapture(t *testing.T) {
	for _, action := range []string{"logs.list", "logs.clear"} {
		t.Run(action, func(t *testing.T) {
			cwd := t.TempDir()
			store, err := storage.New(filepath.Join(cwd, "proxy.db"))
			if err != nil {
				t.Fatalf("storage.New() error = %v", err)
			}
			defer store.Close()
			sys := storage.DefaultSystemConfig()
			sys.TrafficCaptureEnabled = true
			sys.TrafficCaptureFile = "data/traffic-captures.jsonl"
			if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
				t.Fatalf("SaveSystemConfig() error = %v", err)
			}
			handler := New(config.Config{}, nil, nil, nil, logging.New("info", false), nil)
			recorder := capture.New(config.Config{CWD: cwd}, store, logging.New("silent", false))
			ctx := requestlog.WithAccessLogState(context.Background())
			req := httptest.NewRequest(http.MethodPost, "/admin/api", strings.NewReader(fmt.Sprintf(`{"action":"%s"}`, action))).WithContext(ctx)
			rec := httptest.NewRecorder()
			captureSuppressed := false

			recorder.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.handleAPI(w, r, "admin")
				captureSuppressed = capture.Suppressed(r)
			})).ServeHTTP(rec, req)

			if !requestlog.AccessLogSuppressed(ctx) {
				t.Fatalf("%s should suppress its access log entry", action)
			}
			if !captureSuppressed {
				t.Fatalf("%s should suppress its traffic capture record", action)
			}
			if _, err := os.Stat(filepath.Join(cwd, "data", "traffic-captures.jsonl")); !os.IsNotExist(err) {
				t.Fatalf("traffic capture file should not be written, stat err = %v", err)
			}
		})
	}
}

func TestNormalizeTrafficCaptureFileRequiresDataDirectory(t *testing.T) {
	got, errText := normalizeTrafficCaptureFile("./data/traffic-captures.jsonl", "")
	if errText != "" {
		t.Fatalf("normalizeTrafficCaptureFile() error = %q", errText)
	}
	if got != "data/traffic-captures.jsonl" {
		t.Fatalf("normalized path = %q, want data/traffic-captures.jsonl", got)
	}

	invalid := []string{
		"../traffic-captures.jsonl",
		"data/../traffic-captures.jsonl",
		filepath.Join(t.TempDir(), "traffic-captures.jsonl"),
		"traffic-captures.jsonl",
	}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			if got, errText := normalizeTrafficCaptureFile(value, ""); errText == "" {
				t.Fatalf("normalizeTrafficCaptureFile(%q) = %q, want error", value, got)
			}
		})
	}
}

func TestConfigSetImageSettings(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T, context.Context, *Handler)
		payload map[string]any
		want    storage.SystemConfig
	}{
		{
			name: "saves explicit settings",
			payload: map[string]any{
				"imageProxyLimitEnabled":      true,
				"imageProxyMaxConcurrent":     8,
				"imageProxyRequestIntervalMs": 100,
				"imageCacheEnabled":           true,
				"imageCacheTtlDays":           30,
			},
			want: storage.SystemConfig{
				ImageProxyLimitEnabled:      true,
				ImageProxyMaxConcurrent:     8,
				ImageProxyRequestIntervalMS: 100,
				ImageCacheEnabled:           true,
				ImageCacheTTLDays:           30,
			},
		},
		{
			name: "preserves omitted image settings",
			setup: func(t *testing.T, ctx context.Context, handler *Handler) {
				t.Helper()
				saved := storage.DefaultSystemConfig()
				saved.ImageProxyLimitEnabled = true
				saved.ImageProxyMaxConcurrent = 8
				saved.ImageProxyRequestIntervalMS = 100
				saved.ImageCacheEnabled = true
				saved.ImageCacheTTLDays = 30
				if err := handler.store.SaveSystemConfig(ctx, saved); err != nil {
					t.Fatalf("SaveSystemConfig() error = %v", err)
				}
			},
			payload: map[string]any{"logLevel": "debug"},
			want: storage.SystemConfig{
				LogLevel:                    "debug",
				ImageProxyLimitEnabled:      true,
				ImageProxyMaxConcurrent:     8,
				ImageProxyRequestIntervalMS: 100,
				ImageCacheEnabled:           true,
				ImageCacheTTLDays:           30,
			},
		},
		{
			name: "clamps out-of-range settings",
			payload: map[string]any{
				"imageProxyMaxConcurrent":     0,
				"imageProxyRequestIntervalMs": 999999,
				"imageCacheTtlDays":           9999,
			},
			want: storage.SystemConfig{
				ImageProxyMaxConcurrent:     1,
				ImageProxyRequestIntervalMS: 5000,
				ImageCacheTTLDays:           365,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			handler, closeStore := newConfigTestHandler(t)
			defer closeStore()
			if tt.setup != nil {
				tt.setup(t, ctx, handler)
			}

			res := handler.configSet(ctx, map[string]any{"config": tt.payload})
			if res["ok"] != true {
				t.Fatalf("configSet() = %+v", res)
			}
			got, err := handler.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
			if err != nil {
				t.Fatalf("GetSystemConfig() error = %v", err)
			}
			assertImageConfig(t, got, tt.want)
		})
	}
}

func assertImageConfig(t *testing.T, got, want storage.SystemConfig) {
	t.Helper()
	if want.LogLevel != "" && got.LogLevel != want.LogLevel {
		t.Fatalf("LogLevel = %q, want %q", got.LogLevel, want.LogLevel)
	}
	if got.ImageProxyLimitEnabled != want.ImageProxyLimitEnabled ||
		got.ImageProxyMaxConcurrent != want.ImageProxyMaxConcurrent ||
		got.ImageProxyRequestIntervalMS != want.ImageProxyRequestIntervalMS ||
		got.ImageCacheEnabled != want.ImageCacheEnabled ||
		got.ImageCacheTTLDays != want.ImageCacheTTLDays {
		t.Fatalf("image settings = %+v, want %+v", got, want)
	}
}

func newConfigTestHandler(t *testing.T) (*Handler, func()) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatalf("storage.New() error = %v", err)
	}
	handler := New(config.Config{}, store, nil, nil, logging.New("silent", false), nil)
	return handler, func() { _ = store.Close() }
}
