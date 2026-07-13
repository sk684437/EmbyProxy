package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

type Result struct {
	OK         bool
	UID        string
	Role       string
	Status     int
	Error      string
	SessionKey string
	AuthMethod string
}

const AdminTokenNotConfigured = "ADMIN_TOKEN 未配置，请在 .env 或环境变量中设置后重启服务"
const AdminTokenDefault = "ADMIN_TOKEN 不能使用默认值，请在 .env 或环境变量中修改后重启服务"

const defaultAdminToken = "change-me-please"

const (
	adminTokenFailureLimit = 3
	totpFailureLimit       = 3
	authFailureWindow      = 10 * time.Minute
)

const (
	ErrorUnauthorized         = "UNAUTHORIZED"
	ErrorInvalidCredentials   = "INVALID_CREDENTIALS"
	ErrorTOTPRequired         = "TOTP_REQUIRED"
	ErrorTooManyRequests      = "TOO_MANY_REQUESTS"
	ErrorTwoFactorUnavailable = "TWO_FACTOR_UNAVAILABLE"
	ErrorSessionRequired      = "SESSION_REQUIRED"
	ErrorSetupExpired         = "SETUP_EXPIRED"
	ErrorCrossSiteRequest     = "CROSS_SITE_REQUEST"
)

type Checker struct {
	cfg         config.Config
	store       *storage.Store
	authStateMu sync.RWMutex
	mu          sync.Mutex
	totpMu      sync.Mutex
	tokenFails  failureRecords
	totpFails   failureRecords
	sessions    map[string]sessionRecord
	setups      map[string]pendingSetup
	now         func() time.Time
	afterFunc   func(time.Duration, func())
}

type failRecord struct {
	N  int
	TS time.Time
}

type failureRecords struct {
	mu               sync.Mutex
	entries          map[string]failRecord
	cleanupScheduled bool
}

func NewChecker(cfg config.Config, store *storage.Store) *Checker {
	return &Checker{
		cfg:   cfg,
		store: store,
		tokenFails: failureRecords{
			entries: map[string]failRecord{},
		},
		totpFails: failureRecords{
			entries: map[string]failRecord{},
		},
		sessions: map[string]sessionRecord{},
		setups:   map[string]pendingSetup{},
		now:      time.Now,
		afterFunc: func(delay time.Duration, fn func()) {
			time.AfterFunc(delay, fn)
		},
	}
}

func (c *Checker) Check(r *http.Request) Result {
	res, release := c.CheckWithStateGuard(r)
	release()
	return res
}

// CheckWithStateGuard keeps successful token authorization stable until release is called.
// The returned release function must always be called and is a no-op when no lock is held.
func (c *Checker) CheckWithStateGuard(r *http.Request) (Result, func()) {
	if res := c.checkSession(r); res.OK {
		return res, noOpRelease
	}

	got := ExtractToken(r)
	admin := strings.TrimSpace(c.cfg.AdminToken)
	if errText := ValidateAdminToken(admin); errText != "" {
		return Result{Status: http.StatusInternalServerError, Error: errText}, noOpRelease
	}
	if got == "" {
		return Result{Status: http.StatusUnauthorized, Error: ErrorUnauthorized}, noOpRelease
	}
	failureKey := c.ClientIP(r)
	if SafeEqual(got, admin) {
		if !c.clearFailureIfAllowed(&c.tokenFails, failureKey, adminTokenFailureLimit, authFailureWindow) {
			return Result{Status: http.StatusTooManyRequests, Error: ErrorTooManyRequests}, noOpRelease
		}
		if c.cfg.Admin2FADisabled {
			return Result{OK: true, UID: "admin", Role: "admin", AuthMethod: "token"}, noOpRelease
		}
		c.authStateMu.RLock()
		status, err := c.twoFactorStatusLocked(r.Context())
		if err != nil {
			c.authStateMu.RUnlock()
			return Result{Status: http.StatusServiceUnavailable, Error: ErrorTwoFactorUnavailable}, noOpRelease
		}
		if status.Enforced {
			c.authStateMu.RUnlock()
			return Result{Status: http.StatusUnauthorized, Error: ErrorUnauthorized}, noOpRelease
		}
		return Result{OK: true, UID: "admin", Role: "admin", AuthMethod: "token"}, c.authStateMu.RUnlock
	}
	if c.recordFailure(&c.tokenFails, failureKey, adminTokenFailureLimit, authFailureWindow) {
		return Result{Status: http.StatusTooManyRequests, Error: ErrorTooManyRequests}, noOpRelease
	}
	return Result{Status: http.StatusUnauthorized, Error: ErrorUnauthorized}, noOpRelease
}

func noOpRelease() {}

func (c *Checker) ClientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	return ClientIP(r, c.trustsProxy(r.Context()))
}

func (c *Checker) currentTime() time.Time {
	if c != nil && c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Checker) recordFailure(records *failureRecords, key string, maxFail int, window time.Duration) bool {
	now := c.currentTime()
	records.mu.Lock()
	rec := records.entries[key]
	if rec.TS.IsZero() || now.Sub(rec.TS) > window {
		rec = failRecord{TS: now}
	}
	if rec.N >= maxFail {
		records.mu.Unlock()
		return true
	}
	rec.N++
	rec.TS = now
	records.entries[key] = rec
	shouldScheduleCleanup := !records.cleanupScheduled
	if shouldScheduleCleanup {
		records.cleanupScheduled = true
	}
	records.mu.Unlock()
	if shouldScheduleCleanup {
		c.scheduleFailureCleanup(records, window)
	}
	return false
}

func (c *Checker) clearFailure(records *failureRecords, key string) {
	records.mu.Lock()
	delete(records.entries, key)
	records.mu.Unlock()
}

func (c *Checker) clearFailureIfAllowed(records *failureRecords, key string, maxFail int, window time.Duration) bool {
	now := c.currentTime()
	records.mu.Lock()
	defer records.mu.Unlock()
	rec, ok := records.entries[key]
	if ok && now.Sub(rec.TS) > window {
		delete(records.entries, key)
		ok = false
	}
	if ok && rec.N >= maxFail {
		return false
	}
	delete(records.entries, key)
	return true
}

func (c *Checker) failureLimited(records *failureRecords, key string, maxFail int, window time.Duration) bool {
	now := c.currentTime()
	records.mu.Lock()
	defer records.mu.Unlock()
	rec, ok := records.entries[key]
	if ok && now.Sub(rec.TS) > window {
		delete(records.entries, key)
		return false
	}
	return ok && rec.N >= maxFail
}

func (c *Checker) scheduleFailureCleanup(records *failureRecords, window time.Duration) {
	afterFunc := c.afterFunc
	if afterFunc == nil {
		afterFunc = func(delay time.Duration, fn func()) {
			time.AfterFunc(delay, fn)
		}
	}
	afterFunc(window+time.Nanosecond, func() {
		c.cleanupFailures(records, window)
	})
}

func (c *Checker) cleanupFailures(records *failureRecords, window time.Duration) {
	now := c.currentTime()
	records.mu.Lock()
	for key, rec := range records.entries {
		if now.Sub(rec.TS) > window {
			delete(records.entries, key)
		}
	}
	if len(records.entries) == 0 {
		records.cleanupScheduled = false
		records.mu.Unlock()
		return
	}
	records.mu.Unlock()
	c.scheduleFailureCleanup(records, window)
}

func (c *Checker) trustsProxy(ctx context.Context) bool {
	cfg := storage.DefaultSystemConfig()
	if c.store == nil {
		return cfg.TrustProxy
	}
	saved, err := c.store.GetSystemConfig(ctx, cfg)
	if err != nil {
		return cfg.TrustProxy
	}
	return saved.TrustProxy
}

func (c *Checker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := c.Check(r)
		if !res.OK {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(res.Status)
			_, _ = w.Write([]byte(`{"error":"` + res.Error + `"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func SafeEqual(a, b string) bool {
	aSha := sha256.Sum256([]byte(a))
	bSha := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aSha[:], bSha[:]) == 1
}

func ValidateAdminToken(value string) string {
	token := strings.TrimSpace(value)
	if token == "" {
		return AdminTokenNotConfigured
	}
	if strings.EqualFold(token, defaultAdminToken) {
		return AdminTokenDefault
	}
	return ""
}

func ExtractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-Admin-Token"))
}

func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				return first
			}
		}
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}
