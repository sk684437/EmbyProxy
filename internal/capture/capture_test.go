package capture

import (
	"path/filepath"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

func TestCaptureFilePathFallsBackWhenConfiguredPathEscapesData(t *testing.T) {
	cwd := t.TempDir()
	recorder := &Recorder{cfg: config.Config{CWD: cwd}}

	got := recorder.captureFilePath(storage.SystemConfig{TrafficCaptureFile: "../../evil.jsonl"})
	want := filepath.Join(cwd, "data", "traffic-captures.jsonl")
	if got != want {
		t.Fatalf("captureFilePath() = %q, want %q", got, want)
	}
}

func TestCaptureFilePathAllowsDataRelativePath(t *testing.T) {
	cwd := t.TempDir()
	recorder := &Recorder{cfg: config.Config{CWD: cwd}}

	got := recorder.captureFilePath(storage.SystemConfig{TrafficCaptureFile: "data/custom.jsonl"})
	want := filepath.Join(cwd, "data", "custom.jsonl")
	if got != want {
		t.Fatalf("captureFilePath() = %q, want %q", got, want)
	}
}
