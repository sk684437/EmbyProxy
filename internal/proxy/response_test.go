package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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

func TestFetchWithProtocolFallbackClosesDiscardedFirstResponse(t *testing.T) {
	firstBody := newTrackedBody("first")
	secondBody := newTrackedBody("second")
	schemes := []string{}

	h := &Handler{
		manualClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			if len(schemes) == 1 {
				return &http.Response{StatusCode: 530, Header: http.Header{}, Body: firstBody, Request: req}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: secondBody, Request: req}, nil
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.fetchWithProtocolFallback(context.Background(), target, http.MethodGet, http.Header{}, nil, false)
	if err != nil {
		t.Fatalf("fetchWithProtocolFallback() error = %v", err)
	}
	t.Cleanup(func() {
		_ = res.Body.Close()
	})
	if res.Body != secondBody {
		t.Fatal("fetchWithProtocolFallback() did not return the fallback response")
	}
	if got := strings.Join(schemes, ","); got != "https,http" {
		t.Fatalf("schemes = %q, want https,http", got)
	}
	if !firstBody.closed {
		t.Fatal("discarded first response body was not closed")
	}
	if secondBody.closed {
		t.Fatal("returned response body was closed too early")
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
