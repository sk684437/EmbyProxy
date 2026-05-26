package admin

import (
	"net/http"
	"net/http/httptest"
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
