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

	for _, tt := range []struct {
		name      string
		raw       http.Header
		wantKey   string
		wantValue string
	}{
		{
			name:      "authorization",
			raw:       http.Header{"Authorization": {`Emby Client="Original", Device="Original", DeviceId="original", Version="1.0"`}},
			wantKey:   "Authorization",
			wantValue: `Client="Yamby"`,
		},
		{
			name:      "x emby client",
			raw:       http.Header{"X-Emby-Client": {"Original"}},
			wantKey:   "X-Emby-Client",
			wantValue: "Yamby",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			headers := buildDirect(tt.raw)
			if got := headers.Get(tt.wantKey); !strings.Contains(got, tt.wantValue) {
				t.Fatalf("%s = %q, want to contain %q", tt.wantKey, got, tt.wantValue)
			}
			assertNoIdentityHeaders(t, headers, tt.wantKey)
		})
	}

	for _, raw := range []http.Header{{}, {"User-Agent": {"Client/1.0"}}} {
		if got := buildDirect(raw).Get("User-Agent"); got != "Yamby/2.0.3.4(Android" {
			t.Fatalf("User-Agent = %q, want impersonated user agent", got)
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
