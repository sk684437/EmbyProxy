package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

const (
	imageCacheDirName           = "image-cache"
	imageCacheTTLDaysLimit      = 365
	imageCacheMetaCacheTTL      = time.Minute
	imageCacheMetaCacheMaxItems = 4096
)

var imageCacheIgnoredQueryParams = map[string]bool{
	"api_key":                       true,
	"authorization":                 true,
	"x-authorization":               true,
	"x-emby-authorization":          true,
	"x-mediabrowser-authorization":  true,
	"x-emby-token":                  true,
	"x-mediabrowser-token":          true,
	"x-emby-client":                 true,
	"x-mediabrowser-client":         true,
	"x-emby-client-version":         true,
	"x-mediabrowser-client-version": true,
	"x-emby-device-id":              true,
	"x-mediabrowser-device-id":      true,
	"x-emby-device-name":            true,
	"x-mediabrowser-device-name":    true,
	"x-emby-language":               true,
	"x-mediabrowser-language":       true,
}

type imageDiskCache struct {
	dir         string
	ttl         time.Duration
	now         func() time.Time
	cleanupMu   sync.Mutex
	lastCleanup time.Time
	fillMu      sync.Mutex
	fills       map[string]*imageCacheFill
	metaMu      sync.RWMutex
	metaCache   map[string]imageMetaCacheEntry
}

type imageCacheMeta struct {
	KeyHash   string      `json:"keyHash"`
	Status    int         `json:"status"`
	Header    http.Header `json:"header"`
	CreatedAt int64       `json:"createdAt"`
	ExpiresAt int64       `json:"expiresAt"`
}

type imageCachePaths struct {
	hash string
	dir  string
	body string
	meta string
}

type imageCacheFill struct {
	hash string
	done chan struct{}
	once sync.Once
}

type imageMetaCacheEntry struct {
	meta imageCacheMeta
	exp  time.Time
}

func newImageCacheFromSystemConfig(cfg config.Config, sys storage.SystemConfig) *imageDiskCache {
	if !sys.ImageCacheEnabled {
		return nil
	}
	return newImageDiskCache(imageCacheDir(cfg), imageCacheTTL(sys))
}

func (h *Handler) ensureImageCache(ctx context.Context) *imageDiskCache {
	sys := h.systemConfig(ctx)
	if !sys.ImageCacheEnabled {
		h.imageCacheMu.Lock()
		h.imageCache = nil
		h.imageCacheMu.Unlock()
		return nil
	}
	dir := imageCacheDir(h.cfg)
	ttl := imageCacheTTL(sys)
	h.imageCacheMu.Lock()
	defer h.imageCacheMu.Unlock()
	cache := h.imageCache
	if cache == nil || !cache.matches(dir, ttl) {
		cache = newImageDiskCache(dir, ttl)
		h.imageCache = cache
	}
	return cache
}

func imageCacheDir(cfg config.Config) string {
	cwd := strings.TrimSpace(cfg.CWD)
	dir := filepath.Join("data", imageCacheDirName)
	if cwd != "" {
		dir = filepath.Join(cwd, "data", imageCacheDirName)
	}
	return dir
}

func imageCacheTTL(sys storage.SystemConfig) time.Duration {
	days := clampImageConfigInt(sys.ImageCacheTTLDays, 1, imageCacheTTLDaysLimit)
	return time.Duration(days) * 24 * time.Hour
}

func newImageDiskCache(dir string, ttl time.Duration) *imageDiskCache {
	dir = strings.TrimSpace(dir)
	if dir == "" || ttl <= 0 {
		return nil
	}
	return &imageDiskCache{dir: dir, ttl: ttl, now: time.Now}
}

func (c *imageDiskCache) matches(dir string, ttl time.Duration) bool {
	return c != nil && c.dir == strings.TrimSpace(dir) && c.ttl == ttl
}

func imageCacheKey(nodeName string, target *url.URL) string {
	if target == nil {
		return ""
	}
	normalized := *target
	q := normalized.Query()
	for key := range q {
		if imageCacheIgnoredQueryParams[strings.ToLower(key)] {
			delete(q, key)
		}
	}
	normalized.RawQuery = q.Encode()
	return strings.ToLower(strings.TrimSpace(nodeName)) + "\n" + normalized.String()
}

func imageCacheKeyHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum[:])
}

func (c *imageDiskCache) get(r *http.Request, key string, reqOrigin string, env config.ProxyEnv) (*http.Response, bool) {
	if c == nil || key == "" || r == nil || !imageCacheLookupMethod(r.Method) || r.Header.Get("Range") != "" {
		return nil, false
	}
	paths := c.paths(key)
	meta, ok := c.readMeta(paths, key)
	if !ok {
		return nil, false
	}
	if c.expired(meta, c.now()) {
		c.remove(paths)
		return nil, false
	}

	headers := cloneHeader(meta.Header)
	addCORSHeaders(headers, reqOrigin, env)
	headers.Set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Range, Content-Length, Content-Type")
	headers.Del("Vary")
	if imageClientCacheFresh(r, headers) {
		if !c.cachedBodyExists(paths) {
			c.remove(paths)
			return nil, false
		}
		headers.Del("Content-Length")
		return textResponse(http.StatusNotModified, "", headers), true
	}
	if strings.EqualFold(r.Method, http.MethodHead) {
		if !c.cachedBodyExists(paths) {
			c.remove(paths)
			return nil, false
		}
		return textResponse(meta.Status, "", headers), true
	}
	body, err := os.Open(paths.body)
	if err != nil {
		c.remove(paths)
		return nil, false
	}
	return &http.Response{
		StatusCode: meta.Status,
		Status:     fmt.Sprintf("%d %s", meta.Status, http.StatusText(meta.Status)),
		Header:     headers,
		Body:       body,
	}, true
}

func (c *imageDiskCache) wrapStore(r *http.Request, key string, res *http.Response, headers http.Header, onDone ...func()) bool {
	if c == nil || key == "" || r == nil || res == nil || res.Body == nil {
		return false
	}
	if !strings.EqualFold(r.Method, http.MethodGet) || r.Header.Get("Range") != "" || res.StatusCode != http.StatusOK {
		return false
	}
	if !imageCacheableContent(headers) {
		return false
	}
	paths := c.paths(key)
	if err := os.MkdirAll(paths.dir, 0o755); err != nil {
		return false
	}
	tmp, err := os.CreateTemp(paths.dir, filepath.Base(paths.body)+".*.tmp")
	if err != nil {
		return false
	}
	var done func()
	if len(onDone) > 0 {
		done = onDone[0]
	}
	now := c.now().Unix()
	meta := imageCacheMeta{
		KeyHash:   paths.hash,
		Status:    res.StatusCode,
		Header:    imageCacheStoredHeaders(headers),
		CreatedAt: now,
		ExpiresAt: now + int64(c.ttl.Seconds()),
	}
	res.Body = &imageCacheWriteCloser{
		cache:    c,
		src:      res.Body,
		file:     tmp,
		keyHash:  paths.hash,
		tmpBody:  tmp.Name(),
		bodyPath: paths.body,
		metaPath: paths.meta,
		meta:     meta,
		onDone:   done,
	}
	return true
}

func (c *imageDiskCache) CleanupExpired() {
	if c == nil {
		return
	}
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()
	now := c.now()
	if !c.lastCleanup.IsZero() && now.Sub(c.lastCleanup) < time.Hour {
		return
	}
	c.lastCleanup = now
	_ = filepath.WalkDir(c.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".tmp") {
			if info, statErr := d.Info(); statErr == nil && now.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		var meta imageCacheMeta
		if json.Unmarshal(data, &meta) != nil || c.expired(meta, now) {
			body := strings.TrimSuffix(path, ".json") + ".body"
			_ = os.Remove(path)
			_ = os.Remove(body)
			c.deleteCachedMeta(strings.TrimSuffix(d.Name(), ".json"))
		}
		return nil
	})
}

func (c *imageDiskCache) readMeta(paths imageCachePaths, key string) (imageCacheMeta, bool) {
	now := c.now()
	if meta, ok := c.cachedMeta(paths.hash, now); ok {
		return meta, true
	}
	data, err := os.ReadFile(paths.meta)
	if err != nil {
		return imageCacheMeta{}, false
	}
	var meta imageCacheMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		c.remove(paths)
		return imageCacheMeta{}, false
	}
	if meta.KeyHash != imageCacheKeyHash(key) || meta.Status == 0 {
		c.remove(paths)
		return imageCacheMeta{}, false
	}
	if !c.cachedBodyExists(paths) {
		c.remove(paths)
		return imageCacheMeta{}, false
	}
	c.setCachedMeta(paths.hash, meta, now)
	return meta, true
}

func (c *imageDiskCache) expired(meta imageCacheMeta, now time.Time) bool {
	nowUnix := now.Unix()
	ttlSeconds := int64(c.ttl.Seconds())
	if meta.CreatedAt > 0 && ttlSeconds > 0 {
		return meta.CreatedAt+ttlSeconds <= nowUnix
	}
	if meta.ExpiresAt > 0 {
		return meta.ExpiresAt <= nowUnix
	}
	return true
}

func (c *imageDiskCache) paths(key string) imageCachePaths {
	hex := imageCacheKeyHash(key)
	return c.pathsForHash(hex)
}

func (c *imageDiskCache) pathsForHash(hex string) imageCachePaths {
	dir := filepath.Join(c.dir, hex[:2])
	base := filepath.Join(dir, hex)
	return imageCachePaths{hash: hex, dir: dir, body: base + ".body", meta: base + ".json"}
}

func (c *imageDiskCache) remove(paths imageCachePaths) {
	_ = os.Remove(paths.meta)
	_ = os.Remove(paths.body)
	c.deleteCachedMeta(paths.hash)
}

func (c *imageDiskCache) cachedBodyExists(paths imageCachePaths) bool {
	_, err := os.Stat(paths.body)
	return err == nil
}

func (c *imageDiskCache) beginFill(key string) (*imageCacheFill, bool) {
	if c == nil || key == "" {
		return nil, true
	}
	hash := imageCacheKeyHash(key)
	c.fillMu.Lock()
	defer c.fillMu.Unlock()
	if c.fills == nil {
		c.fills = map[string]*imageCacheFill{}
	}
	if fill := c.fills[hash]; fill != nil {
		return fill, false
	}
	fill := &imageCacheFill{hash: hash, done: make(chan struct{})}
	c.fills[hash] = fill
	return fill, true
}

func (c *imageDiskCache) waitFill(ctx context.Context, fill *imageCacheFill) error {
	if fill == nil {
		return nil
	}
	select {
	case <-fill.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *imageDiskCache) finishFill(fill *imageCacheFill) {
	if c == nil || fill == nil {
		return
	}
	fill.once.Do(func() {
		c.fillMu.Lock()
		if c.fills[fill.hash] == fill {
			delete(c.fills, fill.hash)
		}
		c.fillMu.Unlock()
		close(fill.done)
	})
}

func (c *imageDiskCache) cachedMeta(hash string, now time.Time) (imageCacheMeta, bool) {
	if c == nil || hash == "" {
		return imageCacheMeta{}, false
	}
	c.metaMu.RLock()
	entry, ok := c.metaCache[hash]
	c.metaMu.RUnlock()
	if !ok {
		return imageCacheMeta{}, false
	}
	if now.After(entry.exp) {
		c.deleteCachedMeta(hash)
		return imageCacheMeta{}, false
	}
	return cloneImageCacheMeta(entry.meta), true
}

func (c *imageDiskCache) setCachedMeta(hash string, meta imageCacheMeta, now time.Time) {
	if c == nil || hash == "" {
		return
	}
	c.metaMu.Lock()
	defer c.metaMu.Unlock()
	if c.metaCache == nil {
		c.metaCache = map[string]imageMetaCacheEntry{}
	}
	c.metaCache[hash] = imageMetaCacheEntry{meta: cloneImageCacheMeta(meta), exp: now.Add(imageCacheMetaCacheTTL)}
	if len(c.metaCache) <= imageCacheMetaCacheMaxItems {
		return
	}
	for key, entry := range c.metaCache {
		if now.After(entry.exp) {
			delete(c.metaCache, key)
		}
	}
	for len(c.metaCache) > imageCacheMetaCacheMaxItems {
		for key := range c.metaCache {
			delete(c.metaCache, key)
			break
		}
	}
}

func (c *imageDiskCache) deleteCachedMeta(hash string) {
	if c == nil || hash == "" {
		return
	}
	c.metaMu.Lock()
	delete(c.metaCache, hash)
	c.metaMu.Unlock()
}

func cloneImageCacheMeta(meta imageCacheMeta) imageCacheMeta {
	meta.Header = cloneHeader(meta.Header)
	return meta
}

type imageCacheWriteCloser struct {
	cache    *imageDiskCache
	src      io.ReadCloser
	file     *os.File
	keyHash  string
	tmpBody  string
	bodyPath string
	metaPath string
	meta     imageCacheMeta
	onDone   func()
	done     bool
	failed   bool
}

func (w *imageCacheWriteCloser) Read(p []byte) (int, error) {
	n, err := w.src.Read(p)
	if n > 0 && !w.failed {
		if _, writeErr := w.file.Write(p[:n]); writeErr != nil {
			w.failed = true
		}
	}
	if err == io.EOF {
		w.commit()
	}
	return n, err
}

func (w *imageCacheWriteCloser) Close() error {
	if !w.done {
		w.abort()
	}
	return w.src.Close()
}

func (w *imageCacheWriteCloser) commit() {
	if w.done {
		return
	}
	w.done = true
	defer w.finish()
	if w.failed {
		_ = w.file.Close()
		_ = os.Remove(w.tmpBody)
		return
	}
	if err := w.file.Close(); err != nil {
		_ = os.Remove(w.tmpBody)
		return
	}
	if err := os.Rename(w.tmpBody, w.bodyPath); err != nil {
		_ = os.Remove(w.tmpBody)
		return
	}
	data, err := json.Marshal(w.meta)
	if err != nil {
		_ = os.Remove(w.bodyPath)
		return
	}
	tmpMeta := w.metaPath + "." + strconv.FormatInt(time.Now().UnixNano(), 10) + ".tmp"
	if err := os.WriteFile(tmpMeta, data, 0o644); err != nil {
		_ = os.Remove(w.bodyPath)
		return
	}
	if err := os.Rename(tmpMeta, w.metaPath); err != nil {
		_ = os.Remove(tmpMeta)
		_ = os.Remove(w.bodyPath)
		return
	}
	if w.cache != nil {
		w.cache.setCachedMeta(w.keyHash, w.meta, w.cache.now())
	}
}

func (w *imageCacheWriteCloser) abort() {
	w.done = true
	_ = w.file.Close()
	_ = os.Remove(w.tmpBody)
	w.finish()
}

func (w *imageCacheWriteCloser) finish() {
	if w.onDone == nil {
		return
	}
	done := w.onDone
	w.onDone = nil
	done()
}

func imageCacheLookupMethod(method string) bool {
	return strings.EqualFold(method, http.MethodGet) || strings.EqualFold(method, http.MethodHead)
}

func imageCacheableContent(headers http.Header) bool {
	contentType := strings.ToLower(strings.TrimSpace(headers.Get("Content-Type")))
	if contentType == "" {
		return true
	}
	return strings.HasPrefix(contentType, "image/")
}

func imageCacheStoredHeaders(headers http.Header) http.Header {
	out := cloneHeader(headers)
	deleteHeaders(out,
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Origin",
		"Access-Control-Expose-Headers",
		"Content-Length",
		"Set-Cookie",
		"Transfer-Encoding",
		"Vary",
	)
	return out
}

func imageClientCacheFresh(r *http.Request, headers http.Header) bool {
	if r == nil {
		return false
	}
	etag := strings.TrimSpace(headers.Get("ETag"))
	if etag != "" && imageETagMatches(r.Header.Get("If-None-Match"), etag) {
		return true
	}
	ifModifiedSince := strings.TrimSpace(r.Header.Get("If-Modified-Since"))
	lastModified := strings.TrimSpace(headers.Get("Last-Modified"))
	if ifModifiedSince == "" || lastModified == "" {
		return false
	}
	clientTime, err := http.ParseTime(ifModifiedSince)
	if err != nil {
		return false
	}
	cacheTime, err := http.ParseTime(lastModified)
	if err != nil {
		return false
	}
	return !cacheTime.After(clientTime)
}

func imageETagMatches(ifNoneMatch string, etag string) bool {
	ifNoneMatch = strings.TrimSpace(ifNoneMatch)
	if ifNoneMatch == "" {
		return false
	}
	if ifNoneMatch == "*" {
		return true
	}
	for _, value := range strings.Split(ifNoneMatch, ",") {
		if strings.TrimSpace(value) == etag {
			return true
		}
	}
	return false
}
