package capture

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

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
