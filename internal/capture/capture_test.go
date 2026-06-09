package capture

import (
	"path/filepath"
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
