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
	OK     bool
	UID    string
	Role   string
	Status int
	Error  string
}

const AdminTokenNotConfigured = "ADMIN_TOKEN 未配置，请在 .env 或环境变量中设置后重启服务"
const AdminTokenDefault = "ADMIN_TOKEN 不能使用默认值，请在 .env 或环境变量中修改后重启服务"

const defaultAdminToken = "change-me-please"

type Checker struct {
	cfg   config.Config
	store *storage.Store
	mu    sync.Mutex
	fails map[string]failRecord
}

type failRecord struct {
	N  int
	TS time.Time
}

func NewChecker(cfg config.Config, store *storage.Store) *Checker {
	return &Checker{cfg: cfg, store: store, fails: map[string]failRecord{}}
}

func (c *Checker) Check(r *http.Request) Result {
	ip := ClientIP(r, c.trustsProxy(r.Context()))
	now := time.Now()
	window := 10 * time.Minute
	maxFail := 20

	c.mu.Lock()
	defer c.mu.Unlock()
	if now.UnixNano()&63 == 0 {
		for key, rec := range c.fails {
			if now.Sub(rec.TS) > window {
				delete(c.fails, key)
			}
		}
	}
	rec := c.fails[ip]
	if rec.TS.IsZero() || now.Sub(rec.TS) > window {
		rec = failRecord{TS: now}
	}
	got := ExtractToken(r)
	admin := strings.TrimSpace(c.cfg.AdminToken)
	if errText := ValidateAdminToken(admin); errText != "" {
		return Result{Status: http.StatusInternalServerError, Error: errText}
	}
	if got != "" && SafeEqual(got, admin) {
		delete(c.fails, ip)
		return Result{OK: true, UID: "admin", Role: "admin"}
	}
	if rec.N >= maxFail {
		return Result{Status: http.StatusTooManyRequests, Error: "TOO_MANY_REQUESTS"}
	}
	rec.N++
	rec.TS = now
	c.fails[ip] = rec
	return Result{Status: http.StatusUnauthorized, Error: "UNAUTHORIZED"}
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
