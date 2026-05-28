package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackedBody struct {
	reader *strings.Reader
	closed bool
}

func newTrackedBody(value string) *trackedBody {
	return &trackedBody{reader: strings.NewReader(value)}
}

func (b *trackedBody) Read(p []byte) (int, error) {
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func TestFetchTargetDoesNotDowngradeHTTPS(t *testing.T) {
	body := newTrackedBody("first")
	schemes := []string{}

	h := &Handler{
		manualClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			return &http.Response{StatusCode: 530, Header: http.Header{}, Body: body, Request: req}, nil
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.fetchTarget(context.Background(), target, http.MethodGet, http.Header{}, nil, false)
	if err != nil {
		t.Fatalf("fetchTarget() error = %v", err)
	}
	t.Cleanup(func() {
		_ = res.Body.Close()
	})
	if res.Body != body {
		t.Fatal("fetchTarget() did not return the original response")
	}
	if got := strings.Join(schemes, ","); got != "https" {
		t.Fatalf("schemes = %q, want https", got)
	}
	if body.closed {
		t.Fatal("returned response body was closed too early")
	}
}

func TestFetchTargetDoesNotRetryHTTPAfterHTTPSError(t *testing.T) {
	schemes := []string{}
	wantErr := errors.New("upstream timeout")
	h := &Handler{
		manualClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			return nil, wantErr
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.fetchTarget(context.Background(), target, http.MethodGet, http.Header{}, nil, false)
	if !errors.Is(err, wantErr) {
		t.Fatalf("fetchTarget() error = %v, want %v", err, wantErr)
	}
	if got := strings.Join(schemes, ","); got != "https" {
		t.Fatalf("schemes = %q, want https", got)
	}
}

func TestNewProxyHTTPClientUsesTransportTimeouts(t *testing.T) {
	client := newProxyHTTPClient(false)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext is nil")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("ResponseHeaderTimeout was not configured")
	}
	if transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("TLSHandshakeTimeout was not configured")
	}
	if client.CheckRedirect == nil {
		t.Fatal("manual client should disable automatic redirects")
	}

	followClient := newProxyHTTPClient(true)
	if followClient.CheckRedirect != nil {
		t.Fatal("follow client should use default redirect behavior")
	}
}

func TestRawHTTPClientUsesProtectedDirectDialer(t *testing.T) {
	client := newRawHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("raw client should not use environment proxies")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("raw client dialer allowed loopback address")
	}
}

func TestReadProxyRewriteBodyRejectsOversizedBody(t *testing.T) {
	_, err := readProxyRewriteBody(io.LimitReader(repeatingReader{}, proxyRewriteBodyMaxBytes+1))
	if !errors.Is(err, errProxyRewriteBodyTooLarge) {
		t.Fatalf("readProxyRewriteBody() error = %v, want %v", err, errProxyRewriteBodyTooLarge)
	}
}

func TestHandleNodeHidesTargetErrorDetails(t *testing.T) {
	h := &Handler{
		log:          logging.New("silent", false),
		lineBan:      newTTLMap(),
		activeTarget: map[string]string{},
	}
	req := httptest.NewRequest(http.MethodGet, "/node/emby/System/Info", nil)
	node := storage.Node{Name: "node", Target: "http://[::1"}
	parsed := parsedRoute{Name: "node", Path: "/emby/System/Info"}

	res, err := h.handleNode(context.Background(), req, node, parsed, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "::1") || strings.Contains(strings.ToLower(string(body)), "missing") {
		t.Fatalf("response leaked target error details: %q", body)
	}
	if strings.TrimSpace(string(body)) != "Bad Gateway" {
		t.Fatalf("body = %q, want Bad Gateway", body)
	}
}

func TestFinishGeneralResponseRewritesSystemInfoAddresses(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	finalURL, err := url.Parse("https://upstream.example/emby/System/Info/Public")
	if err != nil {
		t.Fatal(err)
	}
	res := bytesResponse(http.StatusOK, []byte(`{"ServerName":"demo","Version":"4.9.3.0","WanAddress":"https://upstream.example","LocalAddress":"http://192.168.1.2:8096"}`), http.Header{
		"Content-Type":   []string{"application/json"},
		"Content-Length": []string{"128"},
	})

	out, err := h.finishGeneralResponse(context.Background(), req, res, storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"}, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/System/Info/Public"}, finalURL, finalURL, http.Header{}, config.ProxyEnv{}, "", false, false, false)
	if err != nil {
		t.Fatalf("finishGeneralResponse() error = %v", err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "upstream.example") || strings.Contains(string(body), "192.168.1.2") {
		t.Fatalf("system info leaked upstream address: %s", body)
	}
	var payload map[string]string
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	want := "https://proxy.example/node/secret"
	if payload["WanAddress"] != want {
		t.Fatalf("WanAddress = %q, want %q", payload["WanAddress"], want)
	}
	if payload["LocalAddress"] != want {
		t.Fatalf("LocalAddress = %q, want %q", payload["LocalAddress"], want)
	}
}

func TestServeHTTPRewritesSystemInfoAddressesWithTargetPathPrefix(t *testing.T) {
	ctx := context.Background()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	if err := store.SaveNode(ctx, "admin", storage.Node{
		Name:           "node",
		Secret:         "secret",
		Target:         "https://upstream.example/proxy",
		DirectExternal: false,
	}); err != nil {
		t.Fatal(err)
	}

	var upstreamRequestURL string
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.manualClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamRequestURL = req.URL.String()
		return bytesResponse(http.StatusOK, []byte(`{"ServerName":"demo","Version":"4.9.3.0","WanAddress":"https://upstream.example","LocalAddress":"http://192.168.1.2:8096"}`), http.Header{
			"Content-Type": []string{"application/json"},
		}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if upstreamRequestURL != "https://upstream.example/proxy/emby/System/Info/Public" {
		t.Fatalf("upstream request URL = %q", upstreamRequestURL)
	}
	if strings.Contains(rr.Body.String(), "upstream.example") || strings.Contains(rr.Body.String(), "192.168.1.2") {
		t.Fatalf("proxied system info leaked upstream address: %s", rr.Body.String())
	}
	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	want := "https://proxy.example/node/secret"
	if payload["WanAddress"] != want || payload["LocalAddress"] != want {
		t.Fatalf("addresses = WanAddress %q, LocalAddress %q; want %q", payload["WanAddress"], payload["LocalAddress"], want)
	}
}

func TestHandleMediaProxyDoesNotCacheImageErrors(t *testing.T) {
	ctx := context.Background()
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.imageLimiter = newImageRequestLimiter(imageProxyMaxConcurrent, 0)
	h.followClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusTooManyRequests, []byte("rate limited"), http.Header{
			"Cache-Control": []string{"public, max-age=60"},
			"Content-Type":  []string{"text/html; charset=UTF-8"},
		}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary", nil)
	finalURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, finalURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() error = %v", err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestHandleMediaProxyServesImageCacheHitBeforeLimiter(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	store, err := storage.New(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.imageCache = newImageDiskCache(filepath.Join(t.TempDir(), "image-cache"), time.Hour)
	h.imageLimiter = newImageRequestLimiter(1, 0)
	upstreamCalls := 0
	h.followClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		if upstreamCalls > 1 {
			return nil, errors.New("unexpected upstream request")
		}
		return bytesResponse(http.StatusOK, []byte("cached-image"), http.Header{
			"Content-Type": []string{"image/jpeg"},
			"ETag":         []string{`"image-v1"`},
		}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=a", nil)
	finalURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=a")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, finalURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() first error = %v", err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "cached-image" {
		t.Fatalf("first body = %q", body)
	}
	if got := AccessLogFields(ctx)["imageCache"]; got != "miss" {
		t.Fatalf("first imageCache log field = %v, want miss", got)
	}
	h.imageLimiter = newImageRequestLimiter(1, time.Hour)
	release, err := h.acquireImageRequestSlot(context.Background(), "node")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	hitBaseCtx := WithAccessLogFields(context.Background())
	hitCtx, cancel := context.WithTimeout(hitBaseCtx, 25*time.Millisecond)
	defer cancel()
	req = httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=a", nil).WithContext(hitCtx)
	finalURL, err = url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=a")
	if err != nil {
		t.Fatal(err)
	}
	res, err = h.handleMediaProxy(hitCtx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, finalURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() cache hit error = %v", err)
	}
	body, err = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "cached-image" {
		t.Fatalf("cache hit body = %q", body)
	}
	if got := AccessLogFields(hitCtx)["imageCache"]; got != "hit" {
		t.Fatalf("cache hit imageCache log field = %v, want hit", got)
	}
	if upstreamCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
	}
}

func TestSetLastResponseClosesReplacedResponse(t *testing.T) {
	h := &Handler{}
	firstBody := newTrackedBody("first")
	secondBody := newTrackedBody("second")
	first := &http.Response{Body: firstBody}
	second := &http.Response{Body: secondBody}

	var last *http.Response
	h.setLastResponse(&last, first)
	if last != first {
		t.Fatal("first response was not stored")
	}
	if firstBody.closed {
		t.Fatal("stored response body was closed")
	}

	h.setLastResponse(&last, second)
	if last != second {
		t.Fatal("second response was not stored")
	}
	if !firstBody.closed {
		t.Fatal("replaced response body was not closed")
	}
	if secondBody.closed {
		t.Fatal("replacement response body was closed")
	}
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
