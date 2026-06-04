package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"embyproxy/internal/config"
)

func TestSendCORSPreflightMatchesArchivedPolicy(t *testing.T) {
	rec := httptest.NewRecorder()

	sendCORSPreflight(rec, "https://player.example", config.ProxyEnv{})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	headers := rec.Result().Header
	if got := headers.Get("Access-Control-Allow-Origin"); got != "https://player.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want reflected origin", got)
	}
	if got := headers.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials = %q, want empty", got)
	}
	if got := headers.Get("Access-Control-Allow-Private-Network"); got != "" {
		t.Fatalf("Access-Control-Allow-Private-Network = %q, want empty", got)
	}
	if got := headers.Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}
}
