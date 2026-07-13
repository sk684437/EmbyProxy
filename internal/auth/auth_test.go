package auth

import (
	"net/http"
	"testing"
	"time"

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

func TestAdminTokenRateLimit(t *testing.T) {
	const adminToken = "strong-random-admin-token"
	type entryPoint struct {
		name         string
		invalidError string
		check        func(*testing.T, *Checker, string) Result
	}
	entryPoints := []entryPoint{
		{
			name:         "protected API",
			invalidError: ErrorUnauthorized,
			check: func(t *testing.T, checker *Checker, token string) Result {
				return checker.Check(newAdminTokenRequest(t, token))
			},
		},
		{
			name:         "login",
			invalidError: ErrorInvalidCredentials,
			check: func(t *testing.T, checker *Checker, token string) Result {
				_, _, res := checker.Login(newAdminTokenRequest(t, token), token, "")
				return res
			},
		},
	}

	for _, entry := range entryPoints {
		t.Run(entry.name, func(t *testing.T) {
			t.Run("blocks all tokens at the limit until the window expires", func(t *testing.T) {
				now := time.Unix(1_000, 0)
				checker := NewChecker(config.Config{AdminToken: adminToken}, nil)
				checker.now = func() time.Time { return now }

				for attempt := 1; attempt <= adminTokenFailureLimit; attempt++ {
					res := entry.check(t, checker, "wrong-admin-token")
					if res.Status != http.StatusUnauthorized || res.Error != entry.invalidError {
						t.Fatalf("attempt %d result = %+v, want 401", attempt, res)
					}
				}
				for _, token := range []string{"wrong-admin-token", adminToken} {
					if res := entry.check(t, checker, token); res.Status != http.StatusTooManyRequests || res.Error != ErrorTooManyRequests {
						t.Fatalf("token %q while limited = %+v, want 429", token, res)
					}
				}

				now = now.Add(authFailureWindow + time.Nanosecond)
				if res := entry.check(t, checker, "wrong-admin-token"); res.Status != http.StatusUnauthorized || res.Error != entry.invalidError {
					t.Fatalf("wrong token after failure window = %+v, want a fresh 401", res)
				}
				if res := entry.check(t, checker, adminToken); !res.OK {
					t.Fatalf("correct token after failure window = %+v, want success", res)
				}
			})

			t.Run("success below the limit clears failures", func(t *testing.T) {
				checker := NewChecker(config.Config{AdminToken: adminToken}, nil)
				checker.now = func() time.Time { return time.Unix(1_000, 0) }

				for attempt := 1; attempt < adminTokenFailureLimit; attempt++ {
					if res := entry.check(t, checker, "wrong-admin-token"); res.Status != http.StatusUnauthorized {
						t.Fatalf("attempt %d result = %+v, want 401", attempt, res)
					}
				}
				if res := entry.check(t, checker, adminToken); !res.OK {
					t.Fatalf("correct token result = %+v, want success", res)
				}
				if res := entry.check(t, checker, "wrong-admin-token"); res.Status != http.StatusUnauthorized || res.Error != entry.invalidError {
					t.Fatalf("result after successful token = %+v, want a fresh 401", res)
				}
			})
		})
	}
}

func TestFailureCleanupReclaimsRecordsAfterRequestsStop(t *testing.T) {
	type scheduledCleanup struct {
		delay time.Duration
		fn    func()
	}

	base := time.Unix(1_000, 0)
	now := base
	checker := NewChecker(config.Config{AdminToken: "strong-random-admin-token"}, nil)
	checker.now = func() time.Time { return now }
	var scheduled []scheduledCleanup
	checker.afterFunc = func(delay time.Duration, fn func()) {
		scheduled = append(scheduled, scheduledCleanup{delay: delay, fn: fn})
	}

	if limited := checker.recordFailure(&checker.tokenFails, "old-ip", adminTokenFailureLimit, authFailureWindow); limited {
		t.Fatal("first old-ip failure was limited")
	}
	if len(scheduled) != 1 || scheduled[0].delay != authFailureWindow+time.Nanosecond {
		t.Fatalf("initial cleanup = %+v, want one cleanup after the failure window", scheduled)
	}
	now = base.Add(authFailureWindow / 2)
	if limited := checker.recordFailure(&checker.tokenFails, "new-ip", adminTokenFailureLimit, authFailureWindow); limited {
		t.Fatal("first new-ip failure was limited")
	}
	if len(scheduled) != 1 {
		t.Fatalf("scheduled cleanup count = %d, want 1", len(scheduled))
	}

	now = base.Add(authFailureWindow + time.Nanosecond)
	scheduled[0].fn()
	checker.tokenFails.mu.Lock()
	_, oldExists := checker.tokenFails.entries["old-ip"]
	_, newExists := checker.tokenFails.entries["new-ip"]
	checker.tokenFails.mu.Unlock()
	if oldExists || !newExists {
		t.Fatalf("records after first cleanup: old=%v new=%v, want false/true", oldExists, newExists)
	}
	if len(scheduled) != 2 || scheduled[1].delay != authFailureWindow+time.Nanosecond {
		t.Fatalf("follow-up cleanup = %+v, want one low-frequency cleanup after another window", scheduled)
	}

	now = base.Add(2*authFailureWindow + 2*time.Nanosecond)
	scheduled[1].fn()
	checker.tokenFails.mu.Lock()
	remaining := len(checker.tokenFails.entries)
	cleanupScheduled := checker.tokenFails.cleanupScheduled
	checker.tokenFails.mu.Unlock()
	if remaining != 0 || cleanupScheduled {
		t.Fatalf("final cleanup left %d records (scheduled=%v), want empty and idle", remaining, cleanupScheduled)
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

func newAdminTokenRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/admin/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}
