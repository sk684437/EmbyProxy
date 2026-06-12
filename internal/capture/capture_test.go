package capture

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

func TestCaptureFilePathStaysWithinDataDirectory(t *testing.T) {
	cwd := t.TempDir()
	recorder := &Recorder{cfg: config.Config{CWD: cwd}}
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "escape falls back", path: "../../evil.jsonl", want: filepath.Join(cwd, "data", "traffic-captures.jsonl")},
		{name: "data relative path", path: "data/custom.jsonl", want: filepath.Join(cwd, "data", "custom.jsonl")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := recorder.captureFilePath(storage.SystemConfig{TrafficCaptureFile: tt.path})
			if got != tt.want {
				t.Fatalf("captureFilePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInboundHeadersToMapIncludesRequestFields(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://proxy.example/emby", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Del("Content-Length")
	req.Host = "proxy.example:8443"
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = 471
	req.Close = true
	req.Trailer = http.Header{
		"X-Foo":   nil,
		"Expires": nil,
	}

	got := inboundHeadersToMap(req)
	tests := []struct {
		key  string
		want string
	}{
		{key: "accept", want: "application/json"},
		{key: "host", want: "proxy.example:8443"},
		{key: "transfer-encoding", want: "chunked"},
		{key: "content-length", want: "471"},
		{key: "connection", want: "close"},
		{key: "trailer", want: "Expires, X-Foo"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got[tt.key] != tt.want {
				t.Fatalf("inboundHeadersToMap()[%q] = %q, want %q", tt.key, got[tt.key], tt.want)
			}
		})
	}
}

func TestSummarizeResponseBufferDecodesCompressedTextCopy(t *testing.T) {
	const body = `{"ok":true,"message":"decoded"}`
	tests := []struct {
		name            string
		contentEncoding string
		encoded         []byte
	}{
		{name: "gzip", contentEncoding: "gzip", encoded: gzipTestBytes(t, []byte(body))},
		{name: "brotli", contentEncoding: "br", encoded: brotliTestBytes(t, []byte(body))},
		{name: "zstd", contentEncoding: "zstd", encoded: zstdTestBytes(t, []byte(body))},
		{name: "deflate zlib", contentEncoding: "deflate", encoded: zlibTestBytes(t, []byte(body))},
		{name: "deflate raw", contentEncoding: "deflate", encoded: rawDeflateTestBytes(t, []byte(body))},
		{name: "encoding chain", contentEncoding: "gzip, br", encoded: brotliTestBytes(t, gzipTestBytes(t, []byte(body)))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{
				"Content-Encoding": []string{tt.contentEncoding},
				"Content-Type":     []string{"application/json; charset=utf-8"},
			}

			got := summarizeResponseBuffer(tt.encoded, int64(len(tt.encoded)), headers, false, storage.DefaultSystemConfig())

			if got.Kind != "json" {
				t.Fatalf("Kind = %q, want json", got.Kind)
			}
			if got.Text != body {
				t.Fatalf("Text = %q, want decoded body", got.Text)
			}
			if got.Bytes != int64(len(body)) {
				t.Fatalf("Bytes = %d, want decoded length %d", got.Bytes, len(body))
			}
		})
	}
}

func TestSummarizeResponseBufferDoesNotDecodeTruncatedResponse(t *testing.T) {
	const body = `{"ok":true}`
	encoded := gzipTestBytes(t, []byte(body))
	headers := http.Header{
		"Content-Encoding": []string{"gzip"},
		"Content-Type":     []string{"application/json"},
	}

	got := summarizeResponseBuffer(encoded, int64(len(encoded)), headers, true, storage.DefaultSystemConfig())

	if got.Kind != "truncated" {
		t.Fatalf("Kind = %q, want truncated", got.Kind)
	}
	if got.Text != "" {
		t.Fatalf("Text = %q, want empty for truncated compressed response", got.Text)
	}
}

func TestSummarizeResponseBufferLimitsDecodedResponse(t *testing.T) {
	encoded := gzipTestBytes(t, []byte(`{"message":"decoded body is too large"}`))
	headers := http.Header{
		"Content-Encoding": []string{"gzip"},
		"Content-Type":     []string{"application/json"},
	}
	cfg := storage.DefaultSystemConfig()
	cfg.TrafficCaptureBodyMax = 8

	got := summarizeResponseBuffer(encoded, int64(len(encoded)), headers, false, cfg)

	if got.Kind != "truncated" {
		t.Fatalf("Kind = %q, want truncated", got.Kind)
	}
	if !got.Truncated {
		t.Fatal("Truncated = false, want true")
	}
	if got.Text != "" {
		t.Fatalf("Text = %q, want empty for oversized decoded response", got.Text)
	}
}

func gzipTestBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
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

func zlibTestBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rawDeflateTestBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
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
