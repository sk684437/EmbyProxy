package auth

import (
	"net/http"
	"testing"

	"embyproxy/internal/config"
)

func TestCheckAdminTokenConfigAndAuthorization(t *testing.T) {
	tests := []struct {
		name        string
		configToken string
		bearerToken string
		wantOK      bool
		wantError   string
	}{
		{name: "missing admin token", bearerToken: "anything", wantError: AdminTokenNotConfigured},
		{name: "configured admin token", configToken: "strong-random-admin-token", bearerToken: "strong-random-admin-token", wantOK: true},
		{name: "short non-default token", configToken: "ok", bearerToken: "ok", wantOK: true},
		{name: "default admin token", configToken: "change-me-please", bearerToken: "change-me-please", wantError: AdminTokenDefault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewChecker(config.Config{AdminToken: tt.configToken}, nil)
			req, err := http.NewRequest(http.MethodPost, "/admin/api", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Authorization", "Bearer "+tt.bearerToken)

			res := checker.Check(req)
			if res.OK != tt.wantOK {
				t.Fatalf("OK = %v, want %v; status=%d error=%q", res.OK, tt.wantOK, res.Status, res.Error)
			}
			if tt.wantOK {
				if res.UID != "admin" || res.Role != "admin" {
					t.Fatalf("identity = %q/%q, want admin/admin", res.UID, res.Role)
				}
				return
			}
			if res.Status != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", res.Status, http.StatusInternalServerError)
			}
			if res.Error != tt.wantError {
				t.Fatalf("error = %q, want %q", res.Error, tt.wantError)
			}
		})
	}
}

func TestClientIPIgnoresForwardedForWhenProxyNotTrusted(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/admin/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	if got := ClientIP(req, false); got != "203.0.113.10" {
		t.Fatalf("ClientIP() = %q, want remote address", got)
	}
}
