package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"embyproxy/internal/auth"
	"embyproxy/internal/buildinfo"
	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func TestServeAdminReportsMissingAdminToken(t *testing.T) {
	cfg := config.Config{}
	handler := New(cfg, nil, auth.NewChecker(cfg, nil), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), auth.AdminTokenNotConfigured) {
		t.Fatalf("body does not include config error: %q", rec.Body.String())
	}
}

func TestServeAdminWithConfiguredTokenReturnsIndex(t *testing.T) {
	cfg := config.Config{AdminToken: "secret"}
	handler := New(cfg, nil, auth.NewChecker(cfg, nil), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `id="loginWrap"`) {
		t.Fatal("expected admin index content")
	}
	if !strings.Contains(rec.Body.String(), `id="appVersion"`) {
		t.Fatal("expected version display container")
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

func TestConfigSetSavesImageSettings(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	res := handler.configSet(ctx, map[string]any{"config": map[string]any{
		"imageProxyLimitEnabled":      true,
		"imageProxyMaxConcurrent":     8,
		"imageProxyRequestIntervalMs": 100,
		"imageCacheEnabled":           true,
		"imageCacheTtlDays":           30,
	}})
	if res["ok"] != true {
		t.Fatalf("configSet() = %+v", res)
	}
	got, err := handler.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
	if err != nil {
		t.Fatalf("GetSystemConfig() error = %v", err)
	}
	if !got.ImageProxyLimitEnabled || got.ImageProxyMaxConcurrent != 8 || got.ImageProxyRequestIntervalMS != 100 || !got.ImageCacheEnabled || got.ImageCacheTTLDays != 30 {
		t.Fatalf("image settings = %+v", got)
	}
}

func TestConfigSetPreservesImageSettingsWhenOmitted(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	saved := storage.DefaultSystemConfig()
	saved.ImageProxyLimitEnabled = true
	saved.ImageProxyMaxConcurrent = 8
	saved.ImageProxyRequestIntervalMS = 100
	saved.ImageCacheEnabled = true
	saved.ImageCacheTTLDays = 30
	if err := handler.store.SaveSystemConfig(ctx, saved); err != nil {
		t.Fatalf("SaveSystemConfig() error = %v", err)
	}

	res := handler.configSet(ctx, map[string]any{"config": map[string]any{
		"logLevel": "debug",
	}})
	if res["ok"] != true {
		t.Fatalf("configSet() = %+v", res)
	}
	got, err := handler.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
	if err != nil {
		t.Fatalf("GetSystemConfig() error = %v", err)
	}
	if got.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want debug", got.LogLevel)
	}
	if !got.ImageProxyLimitEnabled || got.ImageProxyMaxConcurrent != 8 || got.ImageProxyRequestIntervalMS != 100 || !got.ImageCacheEnabled || got.ImageCacheTTLDays != 30 {
		t.Fatalf("image settings = %+v", got)
	}
}

func TestConfigSetClampsImageSettings(t *testing.T) {
	ctx := context.Background()
	handler, closeStore := newConfigTestHandler(t)
	defer closeStore()

	res := handler.configSet(ctx, map[string]any{"config": map[string]any{
		"imageProxyMaxConcurrent":     0,
		"imageProxyRequestIntervalMs": 999999,
		"imageCacheTtlDays":           9999,
	}})
	if res["ok"] != true {
		t.Fatalf("configSet() = %+v", res)
	}
	got, err := handler.store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
	if err != nil {
		t.Fatalf("GetSystemConfig() error = %v", err)
	}
	if got.ImageProxyLimitEnabled || got.ImageProxyMaxConcurrent != 1 || got.ImageProxyRequestIntervalMS != 5000 || got.ImageCacheEnabled || got.ImageCacheTTLDays != 365 {
		t.Fatalf("clamped image settings = %+v", got)
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
