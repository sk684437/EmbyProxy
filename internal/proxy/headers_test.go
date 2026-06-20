package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
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

func TestOutboundHeaderBuildersMapClientIdentityHeaders(t *testing.T) {
	targetURL, err := url.Parse("https://upstream.example/emby/Items")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: true, ImpersonateProfile: identity.DefaultProfile}
	buildDirect := func(raw http.Header) http.Header {
		return buildDirectOutboundHeaders(ids, raw, targetURL, config.ProxyEnv{}, node, "normal")
	}

	for _, tt := range []struct {
		name  string
		build func(http.Header) http.Header
	}{
		{
			name: "clean proxy",
			build: func(raw http.Header) http.Header {
				return buildCleanProxyHeaders(ids, raw, targetURL, node, config.ProxyEnv{}, false)
			},
		},
		{
			name:  "direct",
			build: buildDirect,
		},
		{
			name: "websocket",
			build: func(raw http.Header) http.Header {
				return buildWebSocketHeaders(ids, raw, targetURL, node)
			},
		},
	} {
		t.Run(tt.name+" without identity headers", func(t *testing.T) {
			assertNoIdentityHeaders(t, tt.build(http.Header{"User-Agent": {"Client/1.0"}}))
		})
	}

	for _, raw := range []http.Header{{}, {"User-Agent": {"Client/1.0"}}} {
		if got := buildDirect(raw).Get("User-Agent"); got != "Yamby/2.0.4.3(Android" {
			t.Fatalf("User-Agent = %q, want impersonated user agent", got)
		}
	}
}

func TestOutboundHeaderBuildersStripProxyMetadataHeaders(t *testing.T) {
	targetURL, err := url.Parse("https://upstream.example/emby/Items")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{}
	raw := http.Header{}
	wantAbsent := append([]string{}, cdnMetadataHeaderNames...)
	for _, key := range cdnMetadataHeaderNames {
		raw.Set(key, "proxy-metadata")
	}
	for _, key := range []string{
		"CF-Ray",
		"CF-Visitor",
		"CF-Warp-Tag-Id",
		"Fastly-Client-IP",
		"Fastly-FF",
		"CloudFront-Viewer-Country",
		"CloudFront-Viewer-Address",
		"X-Amz-Cf-Id",
		"X-Edge-Request-Id",
		"X-Fastly-Request-ID",
		"X-Azure-ClientIP",
		"X-Azure-SocketIP",
		"X-Azure-Ref",
		"X-Azure-RequestChain",
		"X-Azure-FDID",
		"X-Azure-Region",
		"X-FD-HealthProbe",
		"Akamai-Client-IP",
		"Akamai-Origin-Hop",
		"X-Vercel-Id",
		"Fly-Client-IP",
	} {
		raw.Set(key, "proxy-prefix-metadata")
		wantAbsent = append(wantAbsent, key)
	}
	raw["cf-worker"] = []string{"lowercase-proxy-metadata"}
	raw["cdn-loop"] = []string{"lowercase-proxy-metadata"}
	wantAbsent = append(wantAbsent, "cf-worker", "cdn-loop")
	raw.Set("User-Agent", "Client/1.0")
	raw.Set("X-Request-Id", "keep-me")

	tests := []struct {
		name  string
		build func(http.Header) http.Header
	}{
		{
			name: "clean proxy",
			build: func(raw http.Header) http.Header {
				return buildCleanProxyHeaders(ids, raw, targetURL, node, config.ProxyEnv{}, false)
			},
		},
		{
			name: "direct",
			build: func(raw http.Header) http.Header {
				return buildDirectOutboundHeaders(ids, raw, targetURL, config.ProxyEnv{}, node, "normal")
			},
		},
		{
			name: "websocket",
			build: func(raw http.Header) http.Header {
				return buildWebSocketHeaders(ids, raw, targetURL, node)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.build(raw)
			assertHeaderKeysAbsent(t, headers, wantAbsent...)
			if got := headers.Get("X-Request-Id"); got != "keep-me" {
				t.Fatalf("X-Request-Id = %q, want keep-me", got)
			}
		})
	}
}

func TestOutboundHeaderBuildersPreserveClientCompressionAndHopByHopHeaders(t *testing.T) {
	targetURL, err := url.Parse("https://upstream.example/emby/Items")
	if err != nil {
		t.Fatal(err)
	}
	ids := identity.NewManager(nil)
	node := storage.Node{Impersonate: true, ImpersonateProfile: identity.DefaultProfile}
	raw := http.Header{
		"Accept-Encoding":  {"gzip, br"},
		"Connection":       {"Keep-Alive"},
		"Keep-Alive":       {"timeout=5"},
		"Proxy-Connection": {"keep-alive"},
		"Te":               {"trailers"},
		"User-Agent":       {"Original/1.0"},
	}
	tests := []struct {
		name  string
		build func(http.Header) http.Header
	}{
		{
			name: "clean proxy",
			build: func(raw http.Header) http.Header {
				return buildCleanProxyHeaders(ids, raw, targetURL, node, config.ProxyEnv{}, false)
			},
		},
		{
			name: "direct",
			build: func(raw http.Header) http.Header {
				return buildDirectOutboundHeaders(ids, raw, targetURL, config.ProxyEnv{}, node, "normal")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := tt.build(raw)
			for key, want := range map[string]string{
				"Accept-Encoding":  "gzip, br",
				"Connection":       "Keep-Alive",
				"Keep-Alive":       "timeout=5",
				"Proxy-Connection": "keep-alive",
				"Te":               "trailers",
			} {
				if got := headers.Get(key); got != want {
					t.Fatalf("%s = %q, want passthrough %q", key, got, want)
				}
			}
		})
	}
}

func assertHeaderKeysAbsent(t *testing.T, headers http.Header, absentKeys ...string) {
	t.Helper()
	for _, absentKey := range absentKeys {
		for key, values := range headers {
			if strings.EqualFold(key, absentKey) {
				t.Fatalf("%s was forwarded as %q", key, values)
			}
		}
	}
}

func assertNoIdentityHeaders(t *testing.T, headers http.Header, except ...string) {
	t.Helper()
	skip := map[string]bool{}
	for _, key := range except {
		skip[http.CanonicalHeaderKey(key)] = true
	}
	for _, key := range []string{"Authorization", "X-Emby-Authorization", "X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Name", "X-Emby-Device-Id"} {
		if skip[http.CanonicalHeaderKey(key)] {
			continue
		}
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want empty", key, got)
		}
	}
}
