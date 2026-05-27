package auth

import (
	"net/http"
	"testing"

	"embyproxy/internal/config"
)

func TestCheckReturnsConfigErrorWhenAdminTokenMissing(t *testing.T) {
	checker := NewChecker(config.Config{}, nil)
	req, err := http.NewRequest(http.MethodPost, "/admin/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer anything")

	res := checker.Check(req)
	if res.OK {
		t.Fatal("expected auth failure")
	}
	if res.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", res.Status, http.StatusInternalServerError)
	}
	if res.Error != AdminTokenNotConfigured {
		t.Fatalf("error = %q, want %q", res.Error, AdminTokenNotConfigured)
	}
}

func TestCheckAcceptsConfiguredAdminToken(t *testing.T) {
	checker := NewChecker(config.Config{AdminToken: "secret"}, nil)
	req, err := http.NewRequest(http.MethodPost, "/admin/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer secret")

	res := checker.Check(req)
	if !res.OK {
		t.Fatalf("expected auth success, got status %d error %q", res.Status, res.Error)
	}
	if res.UID != "admin" || res.Role != "admin" {
		t.Fatalf("identity = %q/%q, want admin/admin", res.UID, res.Role)
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
