package proxy

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"embyproxy/internal/config"
)

func TestImageDiskCacheExpirationUsesCurrentTTL(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cache := newImageDiskCache(t.TempDir(), 7*24*time.Hour)
	meta := imageCacheMeta{
		CreatedAt: now.Add(-2 * 24 * time.Hour).Unix(),
		ExpiresAt: now.Add(-24 * time.Hour).Unix(),
	}
	if cache.expired(meta, now) {
		t.Fatal("cache entry expired by stored ExpiresAt instead of current TTL")
	}
}

func TestImageDiskCacheMetadataDoesNotStoreRawKey(t *testing.T) {
	cache := newImageDiskCache(t.TempDir(), time.Hour)
	rawKey := "node\nhttps://upstream.example/emby/Items/1/Images/Primary?api_key=secret-token"
	res := bytesResponse(http.StatusOK, []byte("image"), http.Header{"Content-Type": []string{"image/jpeg"}})
	cache.wrapStore(httptestRequest(http.MethodGet), rawKey, res, res.Header)
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	data, err := os.ReadFile(cache.paths(rawKey).meta)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "secret-token") || strings.Contains(text, rawKey) {
		t.Fatalf("metadata stored raw cache key: %s", text)
	}
	if !strings.Contains(text, `"keyHash"`) {
		t.Fatalf("metadata missing keyHash: %s", text)
	}
}

func TestImageCacheKeyIgnoresAuthQueryForSharedCache(t *testing.T) {
	first, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=v1&quality=90&X-Emby-Token=account-a&X-Emby-Device-Id=device-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?X-Emby-Device-Id=device-b&quality=90&tag=v1&X-Emby-Token=account-b")
	if err != nil {
		t.Fatal(err)
	}
	if imageCacheKey("node", first) != imageCacheKey("node", second) {
		t.Fatal("auth query parameters should not split image cache entries")
	}

	differentImage, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=v2&quality=90&X-Emby-Token=account-a")
	if err != nil {
		t.Fatal(err)
	}
	if imageCacheKey("node", first) == imageCacheKey("node", differentImage) {
		t.Fatal("content query parameters should still split image cache entries")
	}
}

func TestImageDiskCacheUsesMemoryMetadataAfterDiskRead(t *testing.T) {
	dir := t.TempDir()
	key := "node\nhttps://upstream.example/emby/Items/1/Images/Primary?tag=meta"
	writer := newImageDiskCache(dir, time.Hour)
	res := bytesResponse(http.StatusOK, []byte("image"), http.Header{
		"Content-Type": []string{"image/jpeg"},
		"ETag":         []string{`"meta-v1"`},
	})
	if !writer.wrapStore(httptestRequest(http.MethodGet), key, res, res.Header) {
		t.Fatal("image cache did not wrap cacheable response")
	}
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	cache := newImageDiskCache(dir, time.Hour)
	cached, ok := cache.get(httptestRequest(http.MethodGet), key, "", config.ProxyEnv{})
	if !ok {
		t.Fatal("first cache lookup missed")
	}
	if _, err := io.Copy(io.Discard, cached.Body); err != nil {
		t.Fatal(err)
	}
	_ = cached.Body.Close()

	if err := os.Remove(cache.paths(key).meta); err != nil {
		t.Fatal(err)
	}
	cached, ok = cache.get(httptestRequest(http.MethodGet), key, "", config.ProxyEnv{})
	if !ok {
		t.Fatal("cache lookup missed after metadata file removal")
	}
	body, err := io.ReadAll(cached.Body)
	_ = cached.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "image" {
		t.Fatalf("cached body = %q, want image", body)
	}
}

func TestImageDiskCacheValidatesBodyBeforeFreshClientResponse(t *testing.T) {
	dir := t.TempDir()
	setup := func(t *testing.T, tag string) (*imageDiskCache, string) {
		t.Helper()
		key := "node\nhttps://upstream.example/emby/Items/1/Images/Primary?tag=" + tag
		writer := newImageDiskCache(dir, time.Hour)
		res := bytesResponse(http.StatusOK, []byte("image"), http.Header{
			"Content-Type": []string{"image/jpeg"},
			"ETag":         []string{`"missing-body-v1"`},
		})
		if !writer.wrapStore(httptestRequest(http.MethodGet), key, res, res.Header) {
			t.Fatal("image cache did not wrap cacheable response")
		}
		if _, err := io.Copy(io.Discard, res.Body); err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()

		cache := newImageDiskCache(dir, time.Hour)
		cached, ok := cache.get(httptestRequest(http.MethodGet), key, "", config.ProxyEnv{})
		if !ok {
			t.Fatal("first cache lookup missed")
		}
		_ = cached.Body.Close()
		if err := os.Remove(cache.paths(key).body); err != nil {
			t.Fatal(err)
		}
		return cache, key
	}

	for _, tc := range []struct {
		name string
		req  func() *http.Request
	}{
		{
			name: "not-modified",
			req: func() *http.Request {
				req := httptestRequest(http.MethodGet)
				req.Header.Set("If-None-Match", `"missing-body-v1"`)
				return req
			},
		},
		{
			name: "head",
			req: func() *http.Request {
				return httptestRequest(http.MethodHead)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, key := setup(t, tc.name)
			if cached, ok := cache.get(tc.req(), key, "", config.ProxyEnv{}); ok {
				_ = cached.Body.Close()
				t.Fatal("cache returned early response after cached body was removed")
			}
		})
	}
}

func httptestRequest(method string) *http.Request {
	req, _ := http.NewRequest(method, "https://proxy.example/image", nil)
	return req
}
