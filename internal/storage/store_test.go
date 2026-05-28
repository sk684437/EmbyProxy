package storage

import (
	"context"
	"path/filepath"
	"testing"
)

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
