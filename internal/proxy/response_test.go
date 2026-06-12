package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/requestlog"
	"embyproxy/internal/storage"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type okRoundTripper struct{}

func (okRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return textResponse(http.StatusOK, "ok", nil), nil
}

func newProxyTestHandler(t *testing.T, node storage.Node) *Handler {
	t.Helper()
	if node.Name == "" {
		node.Name = "node"
	}
	if node.Secret == "" {
		node.Secret = "secret"
	}
	if node.Target == "" {
		node.Target = "https://upstream.example"
	}
	store := newProxyTestStore(t)
	if err := store.SaveNode(context.Background(), "admin", node); err != nil {
		t.Fatal(err)
	}
	return New(config.Config{}, store, nil, logging.New("silent", false))
}

func noRedirectClient(rt roundTripFunc) *http.Client {
	return &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func failRoundTripClient(t *testing.T, message string) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Helper()
		t.Fatalf("%s: %s", message, req.URL.String())
		return nil, nil
	})}
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

func TestDoFetchDoesNotDowngradeHTTPS(t *testing.T) {
	body := newTrackedBody("first")
	schemes := []string{}

	h := &Handler{
		noRedirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			return &http.Response{StatusCode: 530, Header: http.Header{}, Body: body, Request: req}, nil
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.doFetch(context.Background(), h.noRedirectClient, target, http.MethodGet, http.Header{}, nil)
	if err != nil {
		t.Fatalf("doFetch() error = %v", err)
	}
	t.Cleanup(func() {
		_ = res.Body.Close()
	})
	if res.Body != body {
		t.Fatal("doFetch() did not return the original response")
	}
	if got := strings.Join(schemes, ","); got != "https" {
		t.Fatalf("schemes = %q, want https", got)
	}
	if body.closed {
		t.Fatal("returned response body was closed too early")
	}
}

func TestSendResponsePreservesContentLengthForPassthrough(t *testing.T) {
	body := []byte("media-body")
	wantLength := fmt.Sprintf("%d", len(body))
	res := bytesResponse(http.StatusPartialContent, body, http.Header{
		"Accept-Ranges":  []string{"bytes"},
		"Content-Length": []string{wantLength},
		"Content-Range":  []string{"bytes 0-9/100"},
		"Content-Type":   []string{"video/mp4"},
	})
	rec := httptest.NewRecorder()

	(&Handler{}).sendResponse(rec, httptest.NewRequest(http.MethodGet, "/video", nil), res)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}
	if got := rec.Header().Get("Content-Length"); got != wantLength {
		t.Fatalf("Content-Length = %q, want %q", got, wantLength)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 0-9/100" {
		t.Fatalf("Content-Range = %q", got)
	}
	if got := rec.Body.String(); got != string(body) {
		t.Fatalf("body = %q, want %q", got, string(body))
	}
}

func TestSendResponseDropsContentLengthForDecodedBody(t *testing.T) {
	res := bytesResponse(http.StatusOK, []byte("decoded"), http.Header{
		"Content-Encoding": []string{"gzip"},
		"Content-Length":   []string{"99"},
		"Content-Type":     []string{"text/plain"},
	})
	res.Uncompressed = true
	rec := httptest.NewRecorder()

	(&Handler{}).sendResponse(rec, httptest.NewRequest(http.MethodGet, "/text", nil), res)

	if got := rec.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
}

func TestSendResponsePreservesContentEncodingForEncodedBody(t *testing.T) {
	body := gzipTestBody(t, "encoded")
	res := bytesResponse(http.StatusOK, body, http.Header{
		"Content-Encoding": []string{"gzip"},
		"Content-Length":   []string{fmt.Sprintf("%d", len(body))},
		"Content-Type":     []string{"text/plain"},
	})
	rec := httptest.NewRecorder()

	(&Handler{}).sendResponse(rec, httptest.NewRequest(http.MethodGet, "/text", nil), res)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := rec.Header().Get("Content-Length"); got != fmt.Sprintf("%d", len(body)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(body))
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Fatalf("body was not preserved as encoded bytes")
	}
}

func TestReadProxyRewriteResponseBodyDecodesEncodedBody(t *testing.T) {
	tests := []struct {
		name            string
		contentEncoding string
		body            []byte
	}{
		{
			name:            "gzip",
			contentEncoding: "gzip",
			body:            gzipTestBody(t, "decoded"),
		},
		{
			name:            "brotli",
			contentEncoding: "br",
			body:            brotliTestBody(t, "decoded"),
		},
		{
			name:            "zstd",
			contentEncoding: "zstd",
			body:            zstdTestBody(t, "decoded"),
		},
		{
			name:            "encoding chain",
			contentEncoding: "gzip, br",
			body:            brotliTestBytes(t, gzipTestBody(t, "decoded")),
		},
		{
			name:            "encoding chain with zstd",
			contentEncoding: "gzip, zstd",
			body:            zstdTestBytes(t, gzipTestBody(t, "decoded")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := bytesResponse(http.StatusOK, tt.body, http.Header{
				"Content-Encoding": []string{tt.contentEncoding},
				"Content-Type":     []string{"application/json"},
			})

			body, encodings, err := readProxyRewriteResponseBody(res)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(encodings, ", "); got != tt.contentEncoding {
				t.Fatalf("encodings = %q, want %q", got, tt.contentEncoding)
			}
			if got := string(body); got != "decoded" {
				t.Fatalf("body = %q, want decoded", got)
			}
		})
	}
}

func TestEncodeProxyRewriteResponseBodyRecompressesWithOriginalEncoding(t *testing.T) {
	tests := []struct {
		name            string
		contentEncoding string
	}{
		{name: "gzip", contentEncoding: "gzip"},
		{name: "brotli", contentEncoding: "br"},
		{name: "zstd", contentEncoding: "zstd"},
		{name: "encoding chain", contentEncoding: "gzip, br"},
		{name: "encoding chain with zstd", contentEncoding: "gzip, zstd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Content-Encoding", tt.contentEncoding)
			headers.Set("Content-Length", "999")
			headers.Set("Content-MD5", "stale")
			encodings := responseContentEncodings(tt.contentEncoding)

			encoded, err := encodeProxyRewriteResponseBody([]byte("rewritten"), encodings, headers)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeProxyRewriteBody(encoded, encodings)
			if err != nil {
				t.Fatal(err)
			}

			if got := string(decoded); got != "rewritten" {
				t.Fatalf("decoded body = %q, want rewritten", got)
			}
			if got := headers.Get("Content-Encoding"); got != tt.contentEncoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, tt.contentEncoding)
			}
			if got := headers.Get("Content-Length"); got != fmt.Sprintf("%d", len(encoded)) {
				t.Fatalf("Content-Length = %q, want %d", got, len(encoded))
			}
			if got := headers.Get("Content-MD5"); got != "" {
				t.Fatalf("Content-MD5 = %q, want empty", got)
			}
		})
	}
}

func gzipTestBody(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func brotliTestBody(t *testing.T, body string) []byte {
	t.Helper()
	return brotliTestBytes(t, []byte(body))
}

func brotliTestBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zstdTestBody(t *testing.T, body string) []byte {
	t.Helper()
	return zstdTestBytes(t, []byte(body))
}

func zstdTestBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestBodyCopyUsesSharedBufferSize(t *testing.T) {
	tests := []struct {
		name string
		copy func(*bodyCopyBufferRecorder) error
	}{
		{
			name: "standard response copy",
			copy: func(body *bodyCopyBufferRecorder) error {
				res := &http.Response{Body: body}
				_, err := (&Handler{}).copyResponseBody(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/video", nil), res)
				return err
			},
		},
		{
			name: "resume chunk copy",
			copy: func(body *bodyCopyBufferRecorder) error {
				buf := getBodyCopyBuffer()
				defer putBodyCopyBuffer(buf)
				_, readErr, writeErr := copyStreamResumeChunk(&bodyCopyWriter{writer: io.Discard}, &bodyCopyReader{reader: body}, buf)
				if writeErr != nil {
					return writeErr
				}
				if !errors.Is(readErr, io.EOF) {
					return fmt.Errorf("read error = %v, want EOF", readErr)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &bodyCopyBufferRecorder{}
			if err := tt.copy(body); err != nil {
				t.Fatalf("copy() error = %v", err)
			}
			if body.maxReadLen != bodyCopyBufferSize {
				t.Fatalf("max read buffer = %d, want %d", body.maxReadLen, bodyCopyBufferSize)
			}
			if bodyCopyBufferSize != 256*1024 {
				t.Fatalf("bodyCopyBufferSize = %d, want 256KB", bodyCopyBufferSize)
			}
		})
	}
}

type bodyCopyBufferRecorder struct {
	maxReadLen int
	reads      int
}

func (r *bodyCopyBufferRecorder) Read(p []byte) (int, error) {
	if len(p) > r.maxReadLen {
		r.maxReadLen = len(p)
	}
	if r.reads > 0 {
		return 0, io.EOF
	}
	r.reads++
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}

func (r *bodyCopyBufferRecorder) Close() error {
	return nil
}

func TestFillContentLengthFromContentRange(t *testing.T) {
	headers := http.Header{
		"Content-Range": []string{"bytes 1024-2047/4096"},
	}

	fillContentLengthFromContentRange(headers)

	if got := headers.Get("Content-Length"); got != "1024" {
		t.Fatalf("Content-Length = %q, want 1024", got)
	}
}

type failingReadBody struct {
	err error
}

func (b failingReadBody) Read([]byte) (int, error) {
	return 0, b.err
}

func (b failingReadBody) Close() error {
	return nil
}

type partialFailBody struct {
	data   []byte
	err    error
	done   bool
	closed bool
}

func (b *partialFailBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, b.err
	}
	b.done = true
	n := copy(p, b.data)
	return n, b.err
}

func (b *partialFailBody) Close() error {
	b.closed = true
	return nil
}

type failingWriteResponseWriter struct {
	header http.Header
	status int
	err    error
}

func (w *failingWriteResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *failingWriteResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingWriteResponseWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestStreamResumeValidatorRequiresStrongValidator(t *testing.T) {
	lastModified := "Tue, 09 Jun 2026 10:00:00 GMT"
	laterDate := "Tue, 09 Jun 2026 10:00:01 GMT"
	sameSecondDate := "Tue, 09 Jun 2026 10:00:00 GMT"
	for _, tt := range []struct {
		name        string
		header      http.Header
		wantOK      bool
		wantIfRange string
	}{
		{
			name: "strong etag wins without date",
			header: http.Header{
				"ETag":          []string{`"media-v1"`},
				"Last-Modified": []string{lastModified},
			},
			wantOK:      true,
			wantIfRange: `"media-v1"`,
		},
		{
			name: "weak etag disables date fallback",
			header: http.Header{
				"ETag":          []string{`W/"media-v1"`},
				"Last-Modified": []string{lastModified},
				"Date":          []string{laterDate},
			},
		},
		{
			name: "last modified needs date",
			header: http.Header{
				"Last-Modified": []string{lastModified},
			},
		},
		{
			name: "last modified same second is not strong enough",
			header: http.Header{
				"Last-Modified": []string{lastModified},
				"Date":          []string{sameSecondDate},
			},
		},
		{
			name: "invalid last modified is rejected",
			header: http.Header{
				"Last-Modified": []string{"not-a-date"},
				"Date":          []string{laterDate},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			validator, ok := newStreamResumeValidator(tt.header)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v; validator=%+v", ok, tt.wantOK, validator)
			}
			if ok && validator.ifRange != tt.wantIfRange {
				t.Fatalf("If-Range = %q, want %q", validator.ifRange, tt.wantIfRange)
			}
		})
	}
}

func TestSendResponseResumesInterruptedPlaybackStream(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-10")
	upstreamErr := errors.New("upstream reset")
	resumeRanges := []string{}
	resumeIfRanges := []string{}
	body := &partialFailBody{data: []byte("hello "), err: upstreamErr}
	client := &http.Client{Transport: roundTripFunc(func(resumeReq *http.Request) (*http.Response, error) {
		resumeRanges = append(resumeRanges, resumeReq.Header.Get("Range"))
		resumeIfRanges = append(resumeIfRanges, resumeReq.Header.Get("If-Range"))
		out := bytesResponse(http.StatusPartialContent, []byte("world"), http.Header{
			"Content-Length": []string{"5"},
			"Content-Range":  []string{"bytes 6-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		})
		out.Request = resumeReq
		return out, nil
	})}
	upstreamReq := httptest.NewRequest(http.MethodGet, "https://cdn.example/video/original.mkv", nil)
	upstreamReq.Header.Set("Range", "bytes=0-10")
	res := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Status:        "206 Partial Content",
		ContentLength: 11,
		Header: http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"11"},
			"Content-Range":  []string{"bytes 0-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		},
		Body:    body,
		Request: upstreamReq,
	}
	attachUpstreamClient(res, client)
	markStreamResumeCandidate(res, "playback")
	if _, ok := (&Handler{}).streamResumePlan(req, res); !ok {
		validator, hasValidator := newStreamResumeValidator(res.Header)
		t.Fatalf("streamResumePlan disabled: source=%q client=%v media=%v accepts=%v validator=%v hasValidator=%v range=%q contentRange=%q", streamResumeSource(res), upstreamClientForResponse(res), streamResumeResponseLooksLikeMedia(res), streamResumeAcceptsBytes(res.Header), validator, hasValidator, res.Request.Header.Get("Range"), res.Header.Get("Content-Range"))
	}
	rec := httptest.NewRecorder()

	(&Handler{log: logging.New("silent", false)}).sendResponse(rec, req, res)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusPartialContent)
	}
	if got := rec.Body.String(); got != "hello world" {
		t.Fatalf("body = %q, want hello world; ranges=%v ifRanges=%v fields=%v", got, resumeRanges, resumeIfRanges, AccessLogFields(ctx))
	}
	if !body.closed {
		t.Fatal("original response body was not closed after resume")
	}
	if got := rec.Header().Get("Content-Length"); got != "11" {
		t.Fatalf("Content-Length = %q, want 11", got)
	}
	if got := strings.Join(resumeRanges, ","); got != "bytes=6-10" {
		t.Fatalf("resume ranges = %q, want bytes=6-10", got)
	}
	if got := strings.Join(resumeIfRanges, ","); got != `"media-v1"` {
		t.Fatalf("resume If-Range = %q, want media-v1", got)
	}
	fields := AccessLogFields(ctx)
	if got := fields["streamResumeAttempts"]; got != 1 {
		t.Fatalf("streamResumeAttempts = %v, want 1", got)
	}
	if got := fields["streamResumeFrom"]; got != int64(6) {
		t.Fatalf("streamResumeFrom = %v, want 6", got)
	}
	if got := fields["streamResumeBytes"]; got != int64(5) {
		t.Fatalf("streamResumeBytes = %v, want 5", got)
	}
	if _, ok := fields["streamResumeError"]; ok {
		t.Fatalf("streamResumeError was set on successful resume: %v", fields["streamResumeError"])
	}
}

func TestSendResponseOmitsStreamResumeErrorBeforeResumeAttempt(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-10")
	upstreamReq := httptest.NewRequest(http.MethodGet, "https://cdn.example/video/original.mkv", nil)
	upstreamReq.Header.Set("Range", "bytes=0-10")
	res := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Status:        "206 Partial Content",
		ContentLength: 11,
		Header: http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"11"},
			"Content-Range":  []string{"bytes 0-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		},
		Body:    io.NopCloser(strings.NewReader("hello world")),
		Request: upstreamReq,
	}
	attachUpstreamClient(res, failRoundTripClient(t, "resume request should not be attempted"))
	markStreamResumeCandidate(res, "playback")
	writer := &failingWriteResponseWriter{err: errors.New("broken pipe")}

	(&Handler{log: logging.New("silent", false)}).sendResponse(writer, req, res)

	fields := AccessLogFields(ctx)
	if got := fields["streamResumeAttempts"]; got != 0 {
		t.Fatalf("streamResumeAttempts = %v, want 0", got)
	}
	if _, ok := fields["streamResumeError"]; ok {
		t.Fatalf("streamResumeError was set before a resume attempt: %v", fields["streamResumeError"])
	}
}

func TestSendResponseLogsStreamResumeErrorForResumeValidationFailure(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-10")
	upstreamErr := errors.New("upstream reset")
	client := &http.Client{Transport: roundTripFunc(func(resumeReq *http.Request) (*http.Response, error) {
		out := bytesResponse(http.StatusPartialContent, []byte("world"), http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"5"},
			"Content-Range":  []string{"bytes 7-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		})
		out.Request = resumeReq
		return out, nil
	})}
	upstreamReq := httptest.NewRequest(http.MethodGet, "https://cdn.example/video/original.mkv", nil)
	upstreamReq.Header.Set("Range", "bytes=0-10")
	res := &http.Response{
		StatusCode:    http.StatusPartialContent,
		Status:        "206 Partial Content",
		ContentLength: 11,
		Header: http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"11"},
			"Content-Range":  []string{"bytes 0-10/11"},
			"Content-Type":   []string{"video/x-matroska"},
			"ETag":           []string{`"media-v1"`},
		},
		Body:    &partialFailBody{data: []byte("hello "), err: upstreamErr},
		Request: upstreamReq,
	}
	attachUpstreamClient(res, client)
	markStreamResumeCandidate(res, "playback")
	rec := httptest.NewRecorder()

	(&Handler{log: logging.New("silent", false)}).sendResponse(rec, req, res)

	fields := AccessLogFields(ctx)
	if got := fields["streamResumeAttempts"]; got != 1 {
		t.Fatalf("streamResumeAttempts = %v, want 1", got)
	}
	if got := fields["streamResumeFrom"]; got != int64(6) {
		t.Fatalf("streamResumeFrom = %v, want 6", got)
	}
	if got, ok := fields["streamResumeError"].(string); !ok || got == "" {
		t.Fatalf("streamResumeError = %v, want non-empty string", fields["streamResumeError"])
	}
}

func TestSendResponseLogsBodyCopyReadError(t *testing.T) {
	log := logging.New("debug", false)
	h := &Handler{log: log}
	wantErr := errors.New("upstream stalled")
	res := &http.Response{
		StatusCode: http.StatusPartialContent,
		Status:     "206 Partial Content",
		Header: http.Header{
			"Content-Range": []string{"bytes 1024-2047/4096"},
		},
		Body: failingReadBody{err: wantErr},
	}
	ctx := WithAccessLogFields(context.Background())
	ctx = context.WithValue(ctx, "requestID", "req-copy")
	ctx = requestlog.WithAccessLogState(ctx)
	requestlog.SetRequestURI(ctx, "/node/<secret>/emby/videos/1/original.mkv")
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=1024-")
	rec := httptest.NewRecorder()

	h.sendResponse(rec, req, res)

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	line := entries[0].Line
	for _, want := range []string{"event=bodyCopyInterrupted", "id=req-copy", "method=GET", "uri=\"/node/<secret>/emby/videos/1/original.mkv\"", "range=\"bytes=1024-\"", "firstReadStatus=none", "side=upstream-read", "error=\"upstream stalled\""} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line = %q, want %q", line, want)
		}
	}
	if got := AccessLogFields(ctx)["firstReadStatus"]; got != "none" {
		t.Fatalf("firstReadStatus access log field = %v, want none", got)
	}
}

func TestSendResponseStoresFirstReadDurationForAccessLog(t *testing.T) {
	h := &Handler{log: logging.New("silent", false)}
	ctx := WithAccessLogFields(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/secret/emby/videos/1/original.mkv", nil).WithContext(ctx)
	res := &http.Response{
		StatusCode: http.StatusPartialContent,
		Status:     "206 Partial Content",
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("hello")),
	}
	rec := httptest.NewRecorder()

	h.sendResponse(rec, req, res)

	firstReadMs, ok := AccessLogFields(ctx)["firstReadMs"].(int64)
	if !ok {
		t.Fatalf("firstReadMs access log field = %T, want int64", AccessLogFields(ctx)["firstReadMs"])
	}
	if firstReadMs < 0 {
		t.Fatalf("firstReadMs = %d, want non-negative", firstReadMs)
	}
}

func TestBodyCopyIssueSidePrefersContextCancellation(t *testing.T) {
	side := bodyCopyIssueSide(
		context.Canceled,
		context.Canceled,
		&bodyCopyReader{lastErr: context.Canceled},
		&bodyCopyWriter{},
	)

	if side != "context" {
		t.Fatalf("side = %q, want context", side)
	}
}

func TestSendResponseOmitsUnredactedURIWhenRequestLogURIIsMissing(t *testing.T) {
	log := logging.New("debug", false)
	h := &Handler{log: log}
	res := &http.Response{
		StatusCode: http.StatusPartialContent,
		Status:     "206 Partial Content",
		Header:     http.Header{},
		Body:       failingReadBody{err: errors.New("upstream stalled")},
	}
	req := httptest.NewRequest(http.MethodGet, "/node/raw-secret/emby/videos/1/original.mkv?api_key=secret-token", nil)
	rec := httptest.NewRecorder()

	h.sendResponse(rec, req, res)

	entries := log.Entries(10)
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	line := entries[0].Line
	if strings.Contains(line, "raw-secret") || strings.Contains(line, "secret-token") || strings.Contains(line, "uri=") {
		t.Fatalf("log line leaked or included unredacted uri: %q", line)
	}
}

func TestServeHTTPMarksAccessLogURIWithRedactedSecret(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	if err := store.SaveNode(ctx, "admin", storage.Node{Name: "node", Secret: "raw-secret", Target: upstream.URL}); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	reqCtx := requestlog.WithAccessLogState(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/node/raw-secret/emby/System/Info?api_key=token", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	got, ok := requestlog.RequestURI(reqCtx)
	if !ok {
		t.Fatal("request URI was not marked for access log")
	}
	if strings.Contains(got, "raw-secret") || strings.Contains(got, "token") {
		t.Fatalf("redacted URI leaked sensitive data: %q", got)
	}
	if got != "/node/<secret>/emby/System/Info?api_key=<redacted>" {
		t.Fatalf("redacted URI = %q", got)
	}
}

func TestDoFetchDoesNotRetryHTTPAfterHTTPSError(t *testing.T) {
	schemes := []string{}
	wantErr := errors.New("upstream timeout")
	h := &Handler{
		noRedirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			return nil, wantErr
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.doFetch(context.Background(), h.noRedirectClient, target, http.MethodGet, http.Header{}, nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("doFetch() error = %v, want %v", err, wantErr)
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
	if !transport.DisableCompression {
		t.Fatal("DisableCompression should preserve client Accept-Encoding exactly")
	}
	if transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("TLSHandshakeTimeout was not configured")
	}
	if client.CheckRedirect == nil {
		t.Fatal("no-redirect client should disable automatic redirects")
	}

	defaultFollowClient := newProxyHTTPClient(true)
	if defaultFollowClient.CheckRedirect != nil {
		t.Fatal("default follow client should use default redirect behavior")
	}
}

func TestNewHandlerSeparatesPlaybackConnectionPools(t *testing.T) {
	h := New(config.Config{}, nil, nil, logging.New("silent", false))
	if h.playbackActionClient.Transport == nil || h.playbackStreamClient.Transport == nil || h.playbackStreamProbeClient.Transport == nil {
		t.Fatal("playback clients should have transports")
	}
	if h.playbackActionClient.Transport == h.playbackStreamClient.Transport {
		t.Fatal("playback action and stream clients should use separate transports")
	}
	if h.playbackStreamClient.Transport != h.playbackStreamProbeClient.Transport {
		t.Fatal("playback stream and probe clients should share one transport")
	}
	if h.playbackStreamProbeClient.CheckRedirect == nil {
		t.Fatal("playback stream probe client should disable automatic redirects")
	}
	if h.playbackActionClient.CheckRedirect != nil || h.playbackStreamClient.CheckRedirect != nil {
		t.Fatal("playback action and stream clients should follow redirects")
	}
}

func TestDoFetchStoresUpstreamPoolAccessLogField(t *testing.T) {
	okClient := func() *http.Client {
		return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, "ok", nil), nil
		})}
	}
	h := &Handler{
		noRedirectClient:          okClient(),
		defaultFollowClient:       okClient(),
		playbackActionClient:      okClient(),
		playbackStreamClient:      okClient(),
		playbackStreamProbeClient: okClient(),
		imageFollowClient:         okClient(),
		rawDirectClient:           &http.Client{Transport: okRoundTripper{}},
	}
	protectedRawClient := &http.Client{Transport: h.rawDirectClient.Transport}
	undefinedClient := okClient()
	target, err := url.Parse("https://upstream.example/emby/System/Ping")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		client *http.Client
		want   string
	}{
		{name: "no redirect", client: h.noRedirectClient, want: upstreamPoolNoRedirect},
		{name: "default follow", client: h.defaultFollowClient, want: upstreamPoolDefaultFollow},
		{name: "playback action", client: h.playbackActionClient, want: upstreamPoolPlaybackAction},
		{name: "playback stream", client: h.playbackStreamClient, want: upstreamPoolPlaybackStream},
		{name: "playback stream probe", client: h.playbackStreamProbeClient, want: upstreamPoolPlaybackStreamProbe},
		{name: "image follow", client: h.imageFollowClient, want: upstreamPoolImageFollow},
		{name: "raw direct", client: h.rawDirectClient, want: upstreamPoolRawDirect},
		{name: "protected raw direct", client: protectedRawClient, want: upstreamPoolRawDirect},
		{name: "undefined", client: undefinedClient, want: upstreamPoolUndefined},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAccessLogFields(context.Background())
			res, err := h.doFetch(ctx, tt.client, target, http.MethodGet, http.Header{}, nil)
			if err != nil {
				t.Fatalf("doFetch() error = %v", err)
			}
			_ = res.Body.Close()
			if got := AccessLogFields(ctx)[accessLogFieldUpstreamPool]; got != tt.want {
				t.Fatalf("upstreamPool = %v, want %s", got, tt.want)
			}
		})
	}
}

func TestHandleMediaProxyChoosesUpstreamClient(t *testing.T) {
	tests := []struct {
		name        string
		requestURI  string
		finalURL    string
		routePath   string
		node        storage.Node
		isPlayback  bool
		isImage     bool
		wantClient  string
		wantStatus  int
		newResponse func() *http.Response
	}{
		{
			name:       "stream playback",
			requestURI: "https://proxy.example/node/emby/Videos/1/stream.mp4",
			finalURL:   "https://upstream.example/emby/Videos/1/stream.mp4",
			routePath:  "/emby/Videos/1/stream.mp4",
			node:       storage.Node{Name: "node", Target: "https://upstream.example"},
			isPlayback: true,
			wantClient: upstreamPoolPlaybackStream,
			wantStatus: http.StatusPartialContent,
			newResponse: func() *http.Response {
				return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
					"Accept-Ranges": []string{"bytes"},
					"Content-Range": []string{"bytes 0-4/5"},
					"Content-Type":  []string{"video/mp4"},
				})
			},
		},
		{
			name:       "direct external non-stream playback action",
			requestURI: "https://proxy.example/node/emby/Sessions/Playing",
			finalURL:   "https://upstream.example/emby/Sessions/Playing",
			routePath:  "/emby/Sessions/Playing",
			node:       storage.Node{Name: "node", Target: "https://upstream.example", DirectExternal: true},
			isPlayback: true,
			wantClient: upstreamPoolPlaybackAction,
			wantStatus: http.StatusOK,
			newResponse: func() *http.Response {
				return textResponse(http.StatusOK, "{}", http.Header{
					"Content-Type": []string{"application/json"},
				})
			},
		},
		{
			name:       "image",
			requestURI: "https://proxy.example/node/emby/Items/1/Images/Primary",
			finalURL:   "https://upstream.example/emby/Items/1/Images/Primary",
			routePath:  "/emby/Items/1/Images/Primary",
			node:       storage.Node{Name: "node", Target: "https://upstream.example"},
			isImage:    true,
			wantClient: upstreamPoolImageFollow,
			wantStatus: http.StatusOK,
			newResponse: func() *http.Response {
				return bytesResponse(http.StatusOK, []byte("image"), http.Header{
					"Content-Type": []string{"image/jpeg"},
				})
			},
		},
		{
			name:       "direct external image path that looks streaming",
			requestURI: "https://proxy.example/node/emby/Items/1/Images/Primary.mp4",
			finalURL:   "https://upstream.example/emby/Items/1/Images/Primary.mp4",
			routePath:  "/emby/Items/1/Images/Primary.mp4",
			node:       storage.Node{Name: "node", Target: "https://upstream.example", DirectExternal: true},
			isPlayback: true,
			isImage:    true,
			wantClient: upstreamPoolImageFollow,
			wantStatus: http.StatusOK,
			newResponse: func() *http.Response {
				return bytesResponse(http.StatusOK, []byte("image"), http.Header{
					"Content-Type": []string{"image/jpeg"},
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAccessLogFields(context.Background())
			calls := map[string]int{}
			successClient := func(name string) *http.Client {
				return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls[name]++
					return tt.newResponse(), nil
				})}
			}
			h := &Handler{
				noRedirectClient:          failRoundTripClient(t, "no-redirect client should not handle "+tt.name),
				defaultFollowClient:       failRoundTripClient(t, "default follow client should not handle "+tt.name),
				playbackActionClient:      failRoundTripClient(t, "playback action client should not handle "+tt.name),
				playbackStreamClient:      failRoundTripClient(t, "playback stream client should not handle "+tt.name),
				playbackStreamProbeClient: failRoundTripClient(t, "playback stream probe client should not handle "+tt.name),
				imageFollowClient:         failRoundTripClient(t, "image follow client should not handle "+tt.name),
			}
			switch tt.wantClient {
			case upstreamPoolPlaybackAction:
				h.playbackActionClient = successClient(tt.wantClient)
			case upstreamPoolPlaybackStream:
				h.playbackStreamClient = successClient(tt.wantClient)
			case upstreamPoolImageFollow:
				h.imageFollowClient = successClient(tt.wantClient)
			default:
				t.Fatalf("unsupported expected client %q", tt.wantClient)
			}
			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil).WithContext(ctx)
			finalURL, err := url.Parse(tt.finalURL)
			if err != nil {
				t.Fatal(err)
			}

			res, err := h.handleMediaProxy(ctx, req, tt.node, parsedRoute{Name: tt.node.Name, Path: tt.routePath}, finalURL, nil, config.ProxyEnv{}, tt.isPlayback, tt.isImage, false, "", "127.0.0.1")
			if err != nil {
				t.Fatalf("handleMediaProxy() error = %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			if calls[tt.wantClient] != 1 {
				t.Fatalf("%s calls = %d, want 1", tt.wantClient, calls[tt.wantClient])
			}
		})
	}
}

func TestHandleNodeRoutesDirectExternalPlaybackActionToPlaybackActionClient(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	actionCalls := 0
	h := newProxyTestHandler(t, storage.Node{DirectExternal: true})
	h.noRedirectClient = failRoundTripClient(t, "general no-redirect client should not handle DirectExternal playback action")
	h.defaultFollowClient = failRoundTripClient(t, "default follow client should not handle DirectExternal playback action")
	h.playbackStreamProbeClient = failRoundTripClient(t, "playback stream probe client should not handle DirectExternal playback action")
	h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not handle DirectExternal playback action")
	h.imageFollowClient = failRoundTripClient(t, "image follow client should not handle DirectExternal playback action")
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		actionCalls++
		if req.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", req.Method)
		}
		if req.URL.String() != "https://upstream.example/emby/Sessions/Playing/Progress?reqformat=json" {
			t.Fatalf("upstream request URL = %q", req.URL.String())
		}
		return textResponse(http.StatusNoContent, "", nil), nil
	})}

	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/secret/emby/Sessions/Playing/Progress?reqformat=json", nil).WithContext(ctx)
	res, err := h.handleNode(ctx, req, storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example", DirectExternal: true}, parsedRoute{Name: "node", Secret: "secret", Path: "/emby/Sessions/Playing/Progress"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	_ = res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusNoContent)
	}
	if actionCalls != 1 {
		t.Fatalf("playback action upstream calls = %d, want 1", actionCalls)
	}
	if got := AccessLogFields(ctx)[accessLogFieldUpstreamPool]; got != upstreamPoolPlaybackAction {
		t.Fatalf("upstreamPool = %v, want %s", got, upstreamPoolPlaybackAction)
	}
}

func TestIsPlaybackStreamRequestClassifiesPlaybackTraffic(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		range_ string
		want   bool
	}{
		{name: "progress", method: http.MethodPost, path: "/emby/Sessions/Playing/Progress"},
		{name: "playback info", method: http.MethodGet, path: "/emby/Items/1/PlaybackInfo"},
		{name: "additional parts", method: http.MethodGet, path: "/emby/Videos/1/AdditionalParts"},
		{name: "original media", method: http.MethodGet, path: "/emby/Videos/1/original.mkv", want: true},
		{name: "stream endpoint", method: http.MethodGet, path: "/emby/Videos/1/stream", want: true},
		{name: "dynamic hls", method: http.MethodGet, path: "/emby/Videos/1/hls1/main/0.ts", want: true},
		{name: "universal audio", method: http.MethodGet, path: "/emby/Audio/1/universal", want: true},
		{name: "ranged video path", method: http.MethodGet, path: "/emby/Videos/1/file", range_: "bytes=0-", want: true},
		{name: "item download", method: http.MethodGet, path: "/emby/Items/1/Download", want: true},
		{name: "media post", method: http.MethodPost, path: "/emby/Videos/1/original.mkv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "https://proxy.example"+tt.path, nil)
			if tt.range_ != "" {
				req.Header.Set("Range", tt.range_)
			}
			finalURL, err := url.Parse("https://upstream.example" + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if got := isPlaybackStreamRequest(req, finalURL); got != tt.want {
				t.Fatalf("isPlaybackStreamRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleMediaProxyUsesImageClientForImageRetries(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	imageCalls := 0
	h := &Handler{
		noRedirectClient:     failRoundTripClient(t, "no-redirect client should not handle image retry"),
		defaultFollowClient:  failRoundTripClient(t, "default follow client should not handle image retry"),
		playbackStreamClient: failRoundTripClient(t, "playback stream client should not handle image retry"),
		imageFollowClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			imageCalls++
			if imageCalls == 1 {
				return textResponse(http.StatusForbidden, "forbidden", nil), nil
			}
			return bytesResponse(http.StatusOK, []byte("image"), http.Header{
				"Content-Type": []string{"image/jpeg"},
			}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary", nil).WithContext(ctx)
	finalURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, finalURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() error = %v", err)
	}
	_ = res.Body.Close()
	if imageCalls != 2 {
		t.Fatalf("image upstream calls = %d, want 2", imageCalls)
	}
}

func TestDialWebSocketTimesOutWaitingForUpgradeResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-stop
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	target, err := url.Parse("http://" + ln.Addr().String() + "/emby/socket")
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, conn, _, err := (&Handler{}).dialWebSocket(ctx, target, http.Header{})
		if conn != nil {
			_ = conn.Close()
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("dialWebSocket() error = nil, want timeout")
		}
	case <-time.After(750 * time.Millisecond):
		close(stop)
		_ = ln.Close()
		<-done
		t.Fatal("dialWebSocket() did not time out waiting for upgrade response")
	}
	close(stop)
	_ = ln.Close()
	<-done
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

func TestHandleNodeStoresTargetDurationForAccessLog(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/System/Ping", nil).WithContext(ctx)
	res, err := h.handleNode(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/System/Ping"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	if _, ok := AccessLogFields(ctx)["responseReadyMs"].(int64); !ok {
		t.Fatalf("responseReadyMs access log field = %T, want int64", AccessLogFields(ctx)["responseReadyMs"])
	}
}

func TestHandleMediaProxyStoresRangeFieldsForStreamingAccessLog(t *testing.T) {
	tests := []struct {
		name       string
		requestURI string
		targetURL  string
	}{
		{
			name:       "video path",
			requestURI: "https://proxy.example/node/emby/videos/1/original.mp4",
			targetURL:  "https://upstream.example/emby/videos/1/original.mp4",
		},
		{
			name:       "smartstrm path",
			requestURI: "https://proxy.example/node/emby/smartstrm?item_id=1&media_id=2",
			targetURL:  "https://upstream.example/emby/smartstrm?item_id=1&media_id=2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithAccessLogFields(context.Background())
			store := newProxyTestStore(t)
			h := New(config.Config{}, store, nil, logging.New("silent", false))
			h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if got := req.Header.Get("Range"); got != "bytes=1024-" {
					t.Fatalf("Range = %q, want bytes=1024-", got)
				}
				if req.URL.String() != tt.targetURL {
					t.Fatalf("upstream request URL = %q, want %q", req.URL.String(), tt.targetURL)
				}
				return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
					"Accept-Ranges":  []string{"bytes"},
					"Content-Range":  []string{"bytes 1024-2047/4096"},
					"Content-Type":   []string{"video/mp4"},
					"Content-Length": []string{"1024"},
				}), nil
			})}
			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil).WithContext(ctx)
			req.Header.Set("Range", "bytes=1024-")
			finalURL, err := url.Parse(tt.targetURL)
			if err != nil {
				t.Fatal(err)
			}

			res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: finalURL.Path}, finalURL, nil, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
			if err != nil {
				t.Fatalf("handleMediaProxy() error = %v", err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()

			assertAccessLogRangeFields(t, ctx, "bytes=1024-", "bytes 1024-2047/4096")
		})
	}
}

func TestHandleMediaProxySkipsRangeFieldsForProgressAccessLog(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	store := newProxyTestStore(t)
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	actionCalls := 0
	h.defaultFollowClient = failRoundTripClient(t, "default follow client should not handle progress requests")
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		actionCalls++
		return textResponse(http.StatusNoContent, "", http.Header{
			"Content-Range": []string{"bytes 0-0/1"},
		}), nil
	})}
	h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not handle progress requests")
	req := httptest.NewRequest(http.MethodPost, "https://proxy.example/node/emby/Sessions/Playing/Progress", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=0-")
	finalURL, err := url.Parse("https://upstream.example/emby/Sessions/Playing/Progress")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleMediaProxy(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Sessions/Playing/Progress"}, finalURL, nil, config.ProxyEnv{}, true, false, false, "", "127.0.0.1")
	if err != nil {
		t.Fatalf("handleMediaProxy() error = %v", err)
	}
	_ = res.Body.Close()
	if actionCalls != 1 {
		t.Fatalf("playback action upstream calls = %d, want 1", actionCalls)
	}

	fields := AccessLogFields(ctx)
	if _, ok := fields["range"]; ok {
		t.Fatalf("range access log field should be absent for progress requests: %v", fields["range"])
	}
	if _, ok := fields["contentRange"]; ok {
		t.Fatalf("contentRange access log field should be absent for progress requests: %v", fields["contentRange"])
	}
}

func TestResponseReadyLogFieldsUsesResponseTarget(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	SetAccessLogField(ctx, "responseReadyMs", int64(68))
	req := httptest.NewRequest(http.MethodGet, "https://www.google.com/search?q=emby", nil)
	res := &http.Response{StatusCode: http.StatusOK, Request: req}

	fields := responseReadyLogFields(ctx, res, map[string]any{
		"id":              "req-1",
		"node":            "node",
		"target":          "https://emby.example",
		"status":          http.StatusOK,
		"responseReadyMs": int64(71),
	})

	if fields["target"] != "https://www.google.com" {
		t.Fatalf("target = %v, want actual target", fields["target"])
	}
	if fields["nodeTarget"] != "https://emby.example" {
		t.Fatalf("nodeTarget = %v, want original node target", fields["nodeTarget"])
	}
	if fields["responseReadyMs"] != int64(68) {
		t.Fatalf("responseReadyMs = %v, want direct response ready duration", fields["responseReadyMs"])
	}
}

func TestHandleNodeStripsClientIPHeadersFromForwardedRequest(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	var upstreamHeaders http.Header
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamHeaders = cloneHeader(req.Header)
		return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/System/Ping", nil)
	setClientIPHeaders(req)

	res, err := h.handleNode(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/System/Ping"}, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleNode() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	assertHeadersAbsent(t, upstreamHeaders, clientIPHeaderKeys...)
}

func TestHandleSTRMStripsClientIPHeadersFromSourceRequest(t *testing.T) {
	var upstreamHeaders http.Header
	h := &Handler{
		playbackActionClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			upstreamHeaders = cloneHeader(req.Header)
			return bytesResponse(http.StatusForbidden, []byte("forbidden"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/movie.strm", nil)
	setClientIPHeaders(req)
	finalURL, err := url.Parse("https://upstream.example/movie.strm")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleSTRM(context.Background(), req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/movie.strm"}, finalURL, nil, config.ProxyEnv{})
	if err != nil {
		t.Fatalf("handleSTRM() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	assertHeadersAbsent(t, upstreamHeaders, clientIPHeaderKeys...)
}

func TestHandleSTRMBlocksPrivateDirectTarget(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	rawCalls := 0
	h := New(config.Config{}, store, nil, logging.New("silent", false))
	h.playbackActionClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte("http://127.0.0.1/private"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rawCalls++
		return bytesResponse(http.StatusOK, []byte("unexpected"), http.Header{"Content-Type": []string{"text/plain"}}), nil
	})}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/movie.strm", nil)
	finalURL, err := url.Parse("https://upstream.example/movie.strm")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.handleSTRM(ctx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/movie.strm"}, finalURL, nil, config.ProxyEnv{ExternalAllowAny: true})
	if err != nil {
		t.Fatalf("handleSTRM() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusForbidden)
	}
	if rawCalls != 0 {
		t.Fatalf("raw direct calls = %d, want 0", rawCalls)
	}
}

func TestHandleDirectDoesNotAppendRequestQuery(t *testing.T) {
	ctx := context.Background()
	rawCalls := 0
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rawCalls++
			if req.URL.String() != "http://8.8.8.8/video.mkv?sign=abc" {
				t.Fatalf("raw URL = %q, want direct URL without request query", req.URL.String())
			}
			return bytesResponse(http.StatusOK, []byte("ok"), http.Header{"Content-Type": []string{"text/plain"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/smartstrm?item_id=1&media_id=2", nil)

	res, err := h.handleDirect(ctx, req, "http://8.8.8.8/video.mkv?sign=abc", config.ProxyEnv{ExternalAllowAny: true}, storage.Node{Name: "node", Target: "https://upstream.example"}, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusOK)
	}
	if rawCalls != 1 {
		t.Fatalf("raw direct calls = %d, want 1", rawCalls)
	}
}

func TestHandleDirectStoresRangeFieldsForStreamingAccessLog(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Range"); got != "bytes=4096-" {
				t.Fatalf("Range = %q, want bytes=4096-", got)
			}
			return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
				"Accept-Ranges":  []string{"bytes"},
				"Content-Range":  []string{"bytes 4096-8191/16384"},
				"Content-Type":   []string{"video/x-matroska"},
				"Content-Length": []string{"4096"},
			}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/http%3A%2F%2F8.8.8.8%2Fvideo.mkv", nil).WithContext(ctx)
	req.Header.Set("Range", "bytes=4096-")

	res, err := h.handleDirect(ctx, req, "http://8.8.8.8/video.mkv", config.ProxyEnv{ExternalAllowAny: true}, storage.Node{Name: "node", Target: "https://upstream.example"}, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()

	assertAccessLogRangeFields(t, ctx, "bytes=4096-", "bytes 4096-8191/16384")
}

func TestRetryableStatusReasonDetectsLocalForbiddenResponses(t *testing.T) {
	res := localForbiddenResponse("direct", "https://115.example/video.mkv?sign=abc")

	fields := retryableStatusLogFields(res, map[string]any{"target": "https://emby.example"})
	if fields["reason"] != "direct-host-not-allowed" {
		t.Fatalf("reason = %v, want direct-host-not-allowed", fields["reason"])
	}
	if fields["target"] != "https://115.example" {
		t.Fatalf("target = %v, want actual target", fields["target"])
	}
	if fields["nodeTarget"] != "https://emby.example" {
		t.Fatalf("nodeTarget = %v, want original node target", fields["nodeTarget"])
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "Forbidden direct host" {
		t.Fatalf("body = %q, want original body", body)
	}

	res = localForbiddenResponse("raw", "https://raw.example/video.mkv")
	fields = retryableStatusLogFields(res, map[string]any{})
	if fields["reason"] != "raw-host-not-allowed" {
		t.Fatalf("raw reason = %v, want raw-host-not-allowed", fields["reason"])
	}
}

func TestHandleDirectBlocksPrivateRedirect(t *testing.T) {
	ctx := context.Background()
	rawCalls := 0
	h := &Handler{
		cfg: config.Config{Defaults: config.Defaults{MaxRetryBodyBytes: 32 * 1024 * 1024}},
		log: logging.New("silent", false),
		rawDirectClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rawCalls++
			return textResponse(http.StatusFound, "", http.Header{"Location": []string{"http://127.0.0.1/private"}}), nil
		})},
	}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/__raw__/http%3A%2F%2F8.8.8.8%2Fstart", nil)

	res, err := h.handleDirect(ctx, req, "http://8.8.8.8/start", config.ProxyEnv{ExternalAllowAny: true}, storage.Node{Name: "node", Target: "https://upstream.example"}, nil)
	if err != nil {
		t.Fatalf("handleDirect() error = %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusForbidden)
	}
	if rawCalls != 1 {
		t.Fatalf("raw direct calls = %d, want 1", rawCalls)
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
	if got, want := out.Header.Get("Content-Length"), fmt.Sprintf("%d", len(body)); got != want {
		t.Fatalf("Content-Length = %q, want %q", got, want)
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

func TestFinishGeneralResponseDoesNotRewritePartialSystemInfo(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/System/Info/Public", nil)
	finalURL, err := url.Parse("https://upstream.example/emby/System/Info/Public")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"WanAddress":"https://upstream.example"}`)
	res := bytesResponse(http.StatusPartialContent, raw, http.Header{
		"Content-Type":   []string{"application/json"},
		"Content-Range":  []string{"bytes 0-39/40"},
		"Content-Length": []string{fmt.Sprintf("%d", len(raw))},
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
	if !bytes.Equal(body, raw) {
		t.Fatalf("body = %q, want original partial body %q", body, raw)
	}
	if got := out.Header.Get("Content-Range"); got != "bytes 0-39/40" {
		t.Fatalf("Content-Range = %q, want original range", got)
	}
}

func TestFinishGeneralResponseBlocksUnsafeCrossHostLocations(t *testing.T) {
	tests := []struct {
		name       string
		requestURI string
		location   string
		node       storage.Node
		route      parsedRoute
		env        config.ProxyEnv
	}{
		{
			name:       "private direct location",
			requestURI: "https://proxy.example/node/emby/redirect",
			location:   "http://127.0.0.1/private",
			node:       storage.Node{Name: "node", Target: "https://upstream.example"},
			route:      parsedRoute{Name: "node", Path: "/emby/redirect"},
			env:        config.ProxyEnv{ExternalAllowAny: true},
		},
		{
			name:       "untrusted public location",
			requestURI: "https://proxy.example/node/secret/emby/redirect-public",
			location:   "http://8.8.8.8/video.mkv?sign=abc",
			node:       storage.Node{Name: "node", Secret: "secret", Target: "https://upstream.example"},
			route:      parsedRoute{Name: "node", Secret: "secret", Path: "/emby/redirect-public"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawCalls := 0
			h := New(config.Config{}, nil, nil, logging.New("silent", false))
			h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				rawCalls++
				return bytesResponse(http.StatusOK, []byte("unexpected"), http.Header{"Content-Type": []string{"text/plain"}}), nil
			})}
			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil)
			finalURL, err := url.Parse("https://upstream.example" + tt.route.Path)
			if err != nil {
				t.Fatal(err)
			}
			res := textResponse(http.StatusFound, "", http.Header{"Location": []string{tt.location}})

			out, err := h.finishGeneralResponse(context.Background(), req, res, tt.node, tt.route, finalURL, finalURL, http.Header{}, tt.env, "", false, false, false)
			if err != nil {
				t.Fatalf("finishGeneralResponse() error = %v", err)
			}
			defer out.Body.Close()
			if out.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", out.StatusCode, http.StatusForbidden)
			}
			if rawCalls != 0 {
				t.Fatalf("raw direct calls = %d, want 0", rawCalls)
			}
		})
	}
}

func TestServeHTTPRewritesSystemInfoAddressesWithTargetPathPrefix(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
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
	h.noRedirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
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

func TestDirectExternalPlaybackUsesObservedUpstreamResponse(t *testing.T) {
	tests := []struct {
		name            string
		requestURI      string
		wantUpstreamURL string
		rangeHeader     string
		upstream        *http.Response
		wantStatus      int
		wantLocation    string
		wantBody        string
		wantMode        string
	}{
		{
			name:            "video non redirect stays proxied",
			requestURI:      "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true",
			wantUpstreamURL: "https://upstream.example/emby/Videos/1/stream.mp4?Static=true",
			rangeHeader:     "bytes=0-",
			upstream: bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
				"Accept-Ranges":  []string{"bytes"},
				"Content-Range":  []string{"bytes 0-4/5"},
				"Content-Type":   []string{"video/mp4"},
				"Content-Length": []string{"5"},
			}),
			wantStatus: http.StatusPartialContent,
			wantBody:   "video",
		},
		{
			name:            "video external redirect is forwarded",
			requestURI:      "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true",
			wantUpstreamURL: "https://upstream.example/emby/Videos/1/stream.mp4?Static=true",
			upstream: textResponse(http.StatusFound, "", http.Header{
				"Location": []string{"http://cdn.example/video.mp4?sign=abc"},
			}),
			wantStatus:   http.StatusFound,
			wantLocation: "http://cdn.example/video.mp4?sign=abc",
			wantMode:     "direct",
		},
		{
			name:            "video same-host redirect is rewritten",
			requestURI:      "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true",
			wantUpstreamURL: "https://upstream.example/emby/Videos/1/stream.mp4?Static=true",
			upstream: textResponse(http.StatusFound, "", http.Header{
				"Location": []string{"https://upstream.example/emby/Videos/2/stream.mp4?Static=true"},
			}),
			wantStatus:   http.StatusFound,
			wantLocation: "https://proxy.example/node/secret/emby/Videos/2/stream.mp4?Static=true",
			wantMode:     "proxy",
		},
		{
			name:            "smartstrm external redirect is forwarded",
			requestURI:      "https://proxy.example/node/secret/emby/smartstrm?item_id=1&media_id=2",
			wantUpstreamURL: "https://upstream.example/emby/smartstrm?item_id=1&media_id=2",
			upstream: textResponse(http.StatusFound, "", http.Header{
				"Location": []string{"http://cdn.example/smartstrm.mp4?sign=abc"},
			}),
			wantStatus:   http.StatusFound,
			wantLocation: "http://cdn.example/smartstrm.mp4?sign=abc",
			wantMode:     "direct",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstreamCalls := 0
			h := newProxyTestHandler(t, storage.Node{DirectExternal: true})
			h.playbackStreamProbeClient = noRedirectClient(func(req *http.Request) (*http.Response, error) {
				upstreamCalls++
				if req.URL.String() != tt.wantUpstreamURL {
					t.Fatalf("upstream request URL = %q, want %q", req.URL.String(), tt.wantUpstreamURL)
				}
				if tt.rangeHeader != "" && req.Header.Get("Range") != tt.rangeHeader {
					t.Fatalf("Range = %q, want %q", req.Header.Get("Range"), tt.rangeHeader)
				}
				return tt.upstream, nil
			})
			h.noRedirectClient = failRoundTripClient(t, "general no-redirect client should not be used for DirectExternal playback probe")
			h.defaultFollowClient = failRoundTripClient(t, "default follow client should not be used for DirectExternal playback probe")
			h.playbackActionClient = failRoundTripClient(t, "playback action client should not be used for DirectExternal playback probe")
			h.playbackStreamClient = failRoundTripClient(t, "playback stream client should not be used for DirectExternal playback probe")
			h.rawDirectClient = failRoundTripClient(t, "raw direct client should not be used for DirectExternal playback response")

			req := httptest.NewRequest(http.MethodGet, tt.requestURI, nil)
			if tt.rangeHeader != "" {
				req.Header.Set("Range", tt.rangeHeader)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if got := rr.Header().Get("Location"); got != tt.wantLocation {
				t.Fatalf("Location = %q, want %q", got, tt.wantLocation)
			}
			if tt.wantBody != "" && rr.Body.String() != tt.wantBody {
				t.Fatalf("body = %q, want %q", rr.Body.String(), tt.wantBody)
			}
			if tt.wantMode != "" {
				result := rr.Result()
				defer result.Body.Close()
				if mode := playbackRedirectMode(req, result); mode != tt.wantMode {
					t.Fatalf("playbackRedirectMode = %q, want %q", mode, tt.wantMode)
				}
			}
			if upstreamCalls != 1 {
				t.Fatalf("upstream calls = %d, want 1", upstreamCalls)
			}
		})
	}
}

func TestSmartSTRMUsesPlaybackProxyWithoutWhitelist(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://upstream.example/emby/smartstrm?item_id=1&media_id=2" {
			t.Fatalf("upstream request URL = %q", req.URL.String())
		}
		return bytesResponse(http.StatusPartialContent, []byte("smartstrm-video"), http.Header{
			"Accept-Ranges": []string{"bytes"},
			"Content-Type":  []string{"video/mp4"},
		}), nil
	})}
	h.rawDirectClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("raw client should not be used for /smartstrm playback proxy")
		return nil, nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/smartstrm?item_id=1&media_id=2", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if rr.Body.String() != "smartstrm-video" {
		t.Fatalf("body = %q, want smartstrm-video", rr.Body.String())
	}
}

func TestServeHTTPLogsPlaybackReadAndWriteBytes(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.playbackStreamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusPartialContent, []byte("video"), http.Header{
			"Accept-Ranges":  []string{"bytes"},
			"Content-Length": []string{"4096"},
			"Content-Range":  []string{"bytes 0-4095/8192"},
			"Content-Type":   []string{"video/mp4"},
		}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Videos/1/stream.mp4?Static=true", nil)
	req.Header.Set("User-Agent", "actual-client")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if rr.Body.String() != "video" {
		t.Fatalf("body = %q, want video", rr.Body.String())
	}

	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		stats, err := h.store.GetTodayStats(ctx)
		if err != nil {
			t.Fatalf("GetTodayStats() error = %v", err)
		}
		for _, row := range stats.Today {
			if row.Node == "node" && row.Client == "actual-client" {
				if row.Bytes != 10 || row.InboundBytes != 5 || row.OutboundBytes != 5 {
					t.Fatalf("play_stats bytes = %d inbound = %d outbound = %d; want 10, 5, 5", row.Bytes, row.InboundBytes, row.OutboundBytes)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("playback stat was not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServeHTTPDoesNotLogImageTrafficAsPlayback(t *testing.T) {
	h := newProxyTestHandler(t, storage.Node{})
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return bytesResponse(http.StatusOK, []byte("image"), http.Header{"Content-Type": []string{"image/jpeg"}}), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Items/1/Images/Primary", nil)
	req.Header.Set("User-Agent", "image-client")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		stats, err := h.store.GetTodayStats(context.Background())
		if err != nil {
			t.Fatalf("GetTodayStats() error = %v", err)
		}
		for _, row := range stats.Today {
			if row.Client == "image-client" {
				t.Fatalf("image request created playback stat: %+v", row)
			}
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPlaybackRedirectModeClassifiesExternalLocations(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/secret/emby/Videos/1/stream.mp4", nil)
	tests := []struct {
		name     string
		location string
		want     string
	}{
		{name: "external absolute", location: "http://cdn.example/video.mp4", want: "direct"},
		{name: "proxy absolute", location: "https://proxy.example/node/secret/emby/Videos/1/stream.mp4", want: "proxy"},
		{name: "relative", location: "/node/secret/emby/Videos/1/stream.mp4", want: "proxy"},
		{name: "empty", location: "", want: "proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := textResponse(http.StatusFound, "", http.Header{"Location": []string{tt.location}})
			if got := playbackRedirectMode(req, res); got != tt.want {
				t.Fatalf("playbackRedirectMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleMediaProxyDoesNotCacheImageErrors(t *testing.T) {
	ctx := context.Background()
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.ImageCacheEnabled = true
	if err := store.SaveSystemConfig(ctx, sys); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
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

func TestHandleMediaProxySkipsImageCacheWhenDisabled(t *testing.T) {
	store := newProxyTestStore(t)
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	upstreamCalls := 0
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		return bytesResponse(http.StatusOK, []byte("image"), http.Header{"Content-Type": []string{"image/jpeg"}}), nil
	})}

	var lastCtx context.Context
	for i := 0; i < 2; i++ {
		reqCtx := WithAccessLogFields(context.Background())
		lastCtx = reqCtx
		req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=disabled", nil).WithContext(reqCtx)
		finalURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=disabled")
		if err != nil {
			t.Fatal(err)
		}
		res, err := h.handleMediaProxy(reqCtx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, finalURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
		if err != nil {
			t.Fatalf("handleMediaProxy() error = %v", err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}
	if upstreamCalls != 2 {
		t.Fatalf("upstream calls = %d, want 2", upstreamCalls)
	}
	if got := AccessLogFields(lastCtx)["imageCache"]; got != "disabled" {
		t.Fatalf("imageCache log field = %v, want disabled", got)
	}
}

func TestHandleMediaProxyServesImageCacheHitBeforeLimiter(t *testing.T) {
	ctx := WithAccessLogFields(context.Background())
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.ImageProxyLimitEnabled = true
	sys.ImageProxyMaxConcurrent = 1
	sys.ImageProxyRequestIntervalMS = 0
	sys.ImageCacheEnabled = true
	if err := store.SaveSystemConfig(ctx, sys); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	upstreamCalls := 0
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
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

func TestHandleMediaProxyCoalescesConcurrentImageCacheMisses(t *testing.T) {
	store := newProxyTestStore(t)
	sys := storage.DefaultSystemConfig()
	sys.ImageCacheEnabled = true
	if err := store.SaveSystemConfig(context.Background(), sys); err != nil {
		t.Fatal(err)
	}
	h := New(config.Config{CWD: t.TempDir()}, store, nil, logging.New("silent", false))
	var upstreamMu sync.Mutex
	upstreamCalls := 0
	h.imageFollowClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamMu.Lock()
		upstreamCalls++
		upstreamMu.Unlock()
		time.Sleep(100 * time.Millisecond)
		return bytesResponse(http.StatusOK, []byte("coalesced-image"), http.Header{
			"Content-Type": []string{"image/jpeg"},
			"ETag":         []string{`"coalesced-v1"`},
		}), nil
	})}

	const requestCount = 8
	start := make(chan struct{})
	errs := make(chan error, requestCount)
	var wg sync.WaitGroup
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			reqCtx, cancel := context.WithTimeout(WithAccessLogFields(context.Background()), 2*time.Second)
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, "https://proxy.example/node/emby/Items/1/Images/Primary?tag=coalesced", nil).WithContext(reqCtx)
			finalURL, err := url.Parse("https://upstream.example/emby/Items/1/Images/Primary?tag=coalesced")
			if err != nil {
				errs <- err
				return
			}
			res, err := h.handleMediaProxy(reqCtx, req, storage.Node{Name: "node", Target: "https://upstream.example"}, parsedRoute{Name: "node", Path: "/emby/Items/1/Images/Primary"}, finalURL, nil, config.ProxyEnv{}, false, true, false, "", "127.0.0.1")
			if err != nil {
				errs <- err
				return
			}
			body, err := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if err != nil {
				errs <- err
				return
			}
			if string(body) != "coalesced-image" {
				errs <- fmt.Errorf("body = %q, want coalesced-image", body)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	upstreamMu.Lock()
	gotCalls := upstreamCalls
	upstreamMu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("upstream calls = %d, want 1", gotCalls)
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

var clientIPHeaderKeys = []string{
	"Remote-Host",
	"X-Forwarded-For",
	"CF-Connecting-IP",
	"X-Remote-Addr",
	"CloudFront-Viewer-Address",
	"X-Azure-ClientIP",
	"X-Envoy-External-Address",
	"X-Original-Forwarded-For",
	"Proxy-Client-IP",
	"Ali-Cdn-Real-IP",
	"Ali-Real-Client-IP",
	"Client-Real-IP",
	"X-Client-Real-IP",
}

func setClientIPHeaders(req *http.Request) {
	for _, key := range clientIPHeaderKeys {
		req.Header.Set(key, "203.0.113.10")
	}
}

func assertAccessLogRangeFields(t *testing.T, ctx context.Context, wantRange, wantContentRange string) {
	t.Helper()
	fields := AccessLogFields(ctx)
	if got := fields["range"]; got != wantRange {
		t.Fatalf("range access log field = %v, want %s", got, wantRange)
	}
	if got := fields["contentRange"]; got != wantContentRange {
		t.Fatalf("contentRange access log field = %v, want %s", got, wantContentRange)
	}
}

func assertHeadersAbsent(t *testing.T, headers http.Header, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s was forwarded as %q", key, got)
		}
	}
}
