package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAdmin2FAConfigCRUDAndCorruption(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, configured, err := store.GetAdmin2FAConfig(ctx); err != nil || configured {
		t.Fatalf("initial config = configured %v, err %v", configured, err)
	}
	want := Admin2FAConfig{Version: 1, Salt: "salt", Nonce: "nonce", Ciphertext: "cipher", EnrolledAt: 1234, LastUsedStep: 42}
	if err := store.SaveAdmin2FAConfig(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, configured, err := store.GetAdmin2FAConfig(ctx)
	if err != nil || !configured || got != want {
		t.Fatalf("stored config = %+v, configured %v, err %v", got, configured, err)
	}
	if err := store.KV().Put(ctx, admin2FAConfigKey, "{broken"); err != nil {
		t.Fatal(err)
	}
	if _, configured, err := store.GetAdmin2FAConfig(ctx); err == nil || !configured {
		t.Fatalf("corrupt config = configured %v, err %v", configured, err)
	}
	if err := store.DeleteAdmin2FAConfig(ctx); err != nil {
		t.Fatal(err)
	}
	if _, configured, err := store.GetAdmin2FAConfig(ctx); err != nil || configured {
		t.Fatalf("deleted config = configured %v, err %v", configured, err)
	}
}

func TestDefaultSystemConfigDoesNotTrustProxyHeaders(t *testing.T) {
	if DefaultSystemConfig().TrustProxy {
		t.Fatal("TrustProxy default should be false")
	}
}

func TestSystemConfigBackfillsImageDefaults(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	fallback := DefaultSystemConfig()
	if err := store.KV().Put(ctx, "system:config", map[string]any{"logLevel": "debug"}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, err := store.GetSystemConfig(ctx, fallback)
	if err != nil {
		t.Fatalf("GetSystemConfig() error = %v", err)
	}
	if got.LogLevel != "debug" {
		t.Fatalf("LogLevel = %q, want debug", got.LogLevel)
	}
	if got.ImageProxyLimitEnabled != fallback.ImageProxyLimitEnabled || got.ImageProxyMaxConcurrent != fallback.ImageProxyMaxConcurrent || got.ImageProxyRequestIntervalMS != fallback.ImageProxyRequestIntervalMS || got.ImageCacheEnabled != fallback.ImageCacheEnabled || got.ImageCacheTTLDays != fallback.ImageCacheTTLDays {
		t.Fatalf("image settings = %+v, want defaults %+v", got, fallback)
	}
}

func TestSystemConfigCacheRefreshesOnSave(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	fallback := DefaultSystemConfig()
	first, err := store.GetSystemConfig(ctx, fallback)
	if err != nil {
		t.Fatalf("GetSystemConfig() error = %v", err)
	}
	if first.LogLevel != fallback.LogLevel {
		t.Fatalf("LogLevel = %q; want fallback %q", first.LogLevel, fallback.LogLevel)
	}

	next := fallback
	next.LogLevel = "debug"
	next.TrustProxy = !fallback.TrustProxy
	if err := store.SaveSystemConfig(ctx, next); err != nil {
		t.Fatalf("SaveSystemConfig() error = %v", err)
	}

	got, err := store.GetSystemConfig(ctx, fallback)
	if err != nil {
		t.Fatalf("GetSystemConfig() after save error = %v", err)
	}
	if got.LogLevel != next.LogLevel || got.TrustProxy != next.TrustProxy {
		t.Fatalf("GetSystemConfig() = %+v; want saved %+v", got, next)
	}
}

func TestTGConfigBackfillsReportEnabledForLegacyEnabledConfig(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.KV().Put(ctx, "tg:config", map[string]any{
		"enabled": true,
		"token":   "token",
		"chat":    "chat",
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := store.GetTGConfig(ctx)
	if err != nil {
		t.Fatalf("GetTGConfig() error = %v", err)
	}
	if !got.ReportEnabled {
		t.Fatalf("ReportEnabled = false, want true for legacy enabled config")
	}
	if got.ServerRemark != "" {
		t.Fatalf("ServerRemark = %q, want empty for legacy config", got.ServerRemark)
	}
}

func TestTGConfigKeepsExplicitReportDisabled(t *testing.T) {
	ctx := context.Background()
	store, err := New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.SaveTGConfig(ctx, TGConfig{
		Enabled:       true,
		Token:         "token",
		Chat:          "chat",
		ReportEnabled: false,
	}); err != nil {
		t.Fatalf("SaveTGConfig() error = %v", err)
	}

	got, err := store.GetTGConfig(ctx)
	if err != nil {
		t.Fatalf("GetTGConfig() error = %v", err)
	}
	if got.ReportEnabled {
		t.Fatalf("ReportEnabled = true, want false")
	}
}
