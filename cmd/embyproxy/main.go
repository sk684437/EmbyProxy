package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"embyproxy/internal/admin"
	"embyproxy/internal/auth"
	"embyproxy/internal/buildinfo"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/proxy"
	"embyproxy/internal/scheduler"
	"embyproxy/internal/storage"
	"embyproxy/internal/telegram"
)

func main() {
	if shouldPrintVersion(os.Args[1:]) {
		fmt.Println(buildinfo.String())
		return
	}

	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	defaultSystemCfg := storage.DefaultSystemConfig()
	log := logging.New(defaultSystemCfg.LogLevel, defaultSystemCfg.LogAccess)
	logBuildInfo(log)
	if errText := auth.ValidateAdminToken(cfg.AdminToken); errText != "" {
		log.Error("startup", "admin token config invalid", map[string]any{"error": errText})
		os.Exit(1)
	}
	store, err := storage.New(cfg.DBPath)
	if err != nil {
		log.Error("startup", "database init failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer store.Close()
	applyRuntimeConfig(context.Background(), store, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ids := identity.NewManager(store)
	if err := ids.Init(ctx); err != nil {
		log.Error("startup", "identity init failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	tg := telegram.New(store, log)
	checker := auth.NewChecker(cfg, store)
	proxyHandler := proxy.New(cfg, store, ids, log)
	adminHandler := admin.New(cfg, store, checker, tg, log, proxyHandler.ResetNodeRoutingState)

	scheduler.New(log, tg, proxyHandler.CleanupTTLMaps).Start(ctx)

	mux := http.NewServeMux()
	mux.Handle("/admin", adminHandler)
	mux.Handle("/admin/", adminHandler)
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		proxyHandler.ServeHTTP(w, r)
	})

	var handler http.Handler = mux
	handler = capture.New(cfg, store, log).Middleware(handler)
	handler = requestMiddleware(log, store, handler)

	server := &http.Server{Addr: cfg.Addr(), Handler: handler}
	go func() {
		listener, err := net.Listen("tcp", cfg.Addr())
		if err != nil {
			log.Error("startup", "server failed", map[string]any{"error": err.Error()})
			stop()
			return
		}
		log.Info("startup", "server listening", map[string]any{"addr": cfg.Addr(), "db": cfg.DBPath})
		logIdentityProfiles(log, ids)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("startup", "server failed", map[string]any{"error": err.Error()})
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "server shutdown failed", map[string]any{"error": err.Error()})
	}
}

func logBuildInfo(log *logging.Logger) {
	info := buildinfo.Current()
	log.Info("startup", "EmbyProxy starting", map[string]any{"version": info.Version, "commit": info.Commit, "builtAt": info.BuiltAt})
}

func shouldPrintVersion(args []string) bool {
	if len(args) != 1 {
		return false
	}
	switch args[0] {
	case "version", "--version", "-v":
		return true
	default:
		return false
	}
}

func logIdentityProfiles(log *logging.Logger, ids *identity.Manager) {
	for _, profile := range identity.ProfileKeys() {
		snap := ids.Snapshot(profile)
		log.Info("startup", "upstream identity profile", map[string]any{
			"profile":   snap.Profile,
			"label":     snap.Label,
			"client":    snap.ClientName,
			"version":   snap.ClientVersion,
			"device":    snap.DeviceName,
			"deviceId":  snap.DeviceID,
			"userAgent": snap.UserAgent,
		})
	}
}

func applyRuntimeConfig(ctx context.Context, store *storage.Store, log *logging.Logger) {
	systemCfg, err := store.GetSystemConfig(ctx, storage.DefaultSystemConfig())
	if err != nil {
		log.Warn("startup", "system config lookup failed", map[string]any{"error": err.Error()})
		return
	}
	log.Configure(systemCfg.LogLevel, systemCfg.LogAccess)
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(chunk []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(chunk)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func requestMiddleware(log *logging.Logger, store *storage.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := log.NextRequestID("")
		ctx := context.WithValue(r.Context(), "requestID", id)
		ctx = proxy.WithAccessLogFields(ctx)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		next.ServeHTTP(sw, r.WithContext(ctx))
		if log.AccessEnabled() {
			meta := map[string]any{"id": id, "status": sw.status, "bytes": sw.bytes, "ms": time.Since(started).Milliseconds(), "ip": auth.ClientIP(r, trustsProxy(ctx, store))}
			for key, value := range proxy.AccessLogFields(ctx) {
				meta[key] = value
			}
			log.Info("access", r.Method+" "+logging.RedactURL(r.URL.RequestURI()), meta)
		}
	})
}

func trustsProxy(ctx context.Context, store *storage.Store) bool {
	cfg := storage.DefaultSystemConfig()
	if store == nil {
		return cfg.TrustProxy
	}
	saved, err := store.GetSystemConfig(ctx, cfg)
	if err != nil {
		return cfg.TrustProxy
	}
	return saved.TrustProxy
}
