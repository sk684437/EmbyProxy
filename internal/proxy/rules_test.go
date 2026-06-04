package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"

	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

func TestIsCapyClient(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		target  string
		want    bool
	}{
		{
			name:    "user agent",
			headers: map[string]string{"User-Agent": "CapyPlayer/1.0"},
			target:  "http://proxy.test/node/emby/System/Info",
			want:    true,
		},
		{
			name:    "emby authorization client",
			headers: map[string]string{"X-Emby-Authorization": `Emby Client="CapyPlayer", Device="iPhone"`},
			target:  "http://proxy.test/node/emby/System/Info",
			want:    true,
		},
		{
			name:    "query client",
			headers: map[string]string{},
			target:  "http://proxy.test/node/emby/System/Info?X-Emby-Client=CapyPlayer",
			want:    true,
		},
		{
			name:    "plain dart is not enough",
			headers: map[string]string{"User-Agent": "Dart/3.8 (dart:io)"},
			target:  "http://proxy.test/node/emby/System/Info",
			want:    false,
		},
		{
			name:    "other client",
			headers: map[string]string{"X-Emby-Client": "Infuse"},
			target:  "http://proxy.test/node/emby/System/Info",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tt.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			if got := isCapyClient(req); got != tt.want {
				t.Fatalf("isCapyClient() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsEmosNodeRequiresCompat(t *testing.T) {
	target, err := url.Parse("https://video.emos.best/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	node := storage.Node{Tag: "emos"}
	env := config.ProxyEnv{EmosMatchHosts: "video.emos.best"}

	if isEmosNode(node, target, env) {
		t.Fatal("isEmosNode matched while EMOS compatibility was disabled")
	}

	env.EmosCompat = true
	if !isEmosNode(node, target, env) {
		t.Fatal("isEmosNode did not match tagged EMOS node when compatibility was enabled")
	}
}

func TestResolveTargetURLCarriesRawQueryWithoutParsingWhenBaseHasNoQuery(t *testing.T) {
	base, err := url.Parse("https://emby.example.test/base")
	if err != nil {
		t.Fatal(err)
	}
	rawQuery := "Fields=Path&Fields=MediaSources&X-Emby-Token=abc%2F123"

	got := resolveTargetURL(base, "/emby/Items", rawQuery)

	if got.String() != "https://emby.example.test/base/emby/Items?"+rawQuery {
		t.Fatalf("resolveTargetURL() = %q", got.String())
	}
	if got.RawQuery != rawQuery {
		t.Fatalf("RawQuery = %q, want %q", got.RawQuery, rawQuery)
	}
}

func TestResolveTargetURLMergesBaseQueryAndKeepsRepeatedRequestValues(t *testing.T) {
	base, err := url.Parse("https://emby.example.test/base?api_key=node-key&lang=zh")
	if err != nil {
		t.Fatal(err)
	}

	got := resolveTargetURL(base, "/emby/Items", "api_key=req-key&Fields=Path&Fields=MediaSources")
	query := got.Query()

	if got.Path != "/base/emby/Items" {
		t.Fatalf("Path = %q, want %q", got.Path, "/base/emby/Items")
	}
	if gotAPIKey := query.Get("api_key"); gotAPIKey != "req-key" {
		t.Fatalf("api_key = %q, want req-key", gotAPIKey)
	}
	if gotLang := query.Get("lang"); gotLang != "zh" {
		t.Fatalf("lang = %q, want zh", gotLang)
	}
	fields := query["Fields"]
	if len(fields) != 2 || fields[0] != "Path" || fields[1] != "MediaSources" {
		t.Fatalf("Fields = %#v, want [Path MediaSources]", fields)
	}
}

func TestRawHostAllowedBlocksPrivateDestinations(t *testing.T) {
	h := &Handler{}
	node := storage.Node{Target: "https://example.test"}
	env := config.ProxyEnv{ExternalAllowAny: true}

	tests := []string{
		"http://127.0.0.1/latest/meta-data/",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.64.0.1/private",
		"http://[::1]/private",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if h.rawHostAllowed(context.Background(), node, u, env) {
				t.Fatalf("rawHostAllowed(%q) = true, want false", raw)
			}
		})
	}
}

func TestRawHostAllowedPermitsPublicLiteralWhenAllowAny(t *testing.T) {
	h := &Handler{}
	node := storage.Node{Target: "https://example.test"}
	u, err := url.Parse("http://8.8.8.8/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if !h.rawHostAllowed(context.Background(), node, u, config.ProxyEnv{ExternalAllowAny: true}) {
		t.Fatal("rawHostAllowed() rejected public literal IP with ExternalAllowAny")
	}
}

func TestRawIPBlockedRejectsSpecialUseDestinations(t *testing.T) {
	blocked := []string{
		"0.0.0.1",
		"100.64.0.1",
		"198.18.0.1",
		"192.0.2.1",
		"192.31.196.1",
		"192.52.193.1",
		"192.175.48.1",
		"198.51.100.1",
		"203.0.113.1",
		"240.0.0.1",
		"255.255.255.255",
		"64:ff9b::a00:1",
		"64:ff9b:1::a00:1",
		"100::1",
		"2001::1",
		"2001:db8::1",
		"2002:a00:1::1",
		"2620:4f:8000::1",
		"3fff::1",
		"5f00::1",
		"fc00::1",
		"fe80::1",
		"fec0::1",
	}
	for _, value := range blocked {
		t.Run(value, func(t *testing.T) {
			ip := net.ParseIP(value)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", value)
			}
			if !rawIPBlocked(ip) {
				t.Fatalf("rawIPBlocked(%q) = false, want true", value)
			}
		})
	}
}

func TestRawIPBlockedAllowsPublicDestinations(t *testing.T) {
	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
	}
	for _, value := range allowed {
		t.Run(value, func(t *testing.T) {
			ip := net.ParseIP(value)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", value)
			}
			if rawIPBlocked(ip) {
				t.Fatalf("rawIPBlocked(%q) = true, want false", value)
			}
		})
	}
}
