package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"embyproxy/internal/auth"
	"embyproxy/internal/config"
)

func TestServeAdminReportsMissingAdminToken(t *testing.T) {
	cfg := config.Config{}
	handler := New(cfg, nil, auth.NewChecker(cfg, nil), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), auth.AdminTokenNotConfigured) {
		t.Fatalf("body does not include config error: %q", rec.Body.String())
	}
}

func TestServeAdminWithConfiguredTokenReturnsIndex(t *testing.T) {
	cfg := config.Config{AdminToken: "secret"}
	handler := New(cfg, nil, auth.NewChecker(cfg, nil), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), `id="loginWrap"`) {
		t.Fatal("expected admin index content")
	}
}

func TestNormalizeTrafficCaptureFileRequiresDataDirectory(t *testing.T) {
	got, errText := normalizeTrafficCaptureFile("./data/traffic-captures.jsonl", "")
	if errText != "" {
		t.Fatalf("normalizeTrafficCaptureFile() error = %q", errText)
	}
	if got != "data/traffic-captures.jsonl" {
		t.Fatalf("normalized path = %q, want data/traffic-captures.jsonl", got)
	}

	invalid := []string{
		"../traffic-captures.jsonl",
		"data/../traffic-captures.jsonl",
		filepath.Join(t.TempDir(), "traffic-captures.jsonl"),
		"traffic-captures.jsonl",
	}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			if got, errText := normalizeTrafficCaptureFile(value, ""); errText == "" {
				t.Fatalf("normalizeTrafficCaptureFile(%q) = %q, want error", value, got)
			}
		})
	}
}
