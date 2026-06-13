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

func TestIsPlaybackPathSupportsOptionalEmbyPrefix(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "emby video stream", path: "/emby/Videos/1/stream.mp4", want: true},
		{name: "bare video stream", path: "/Videos/1/stream.mp4", want: true},
		{name: "bare original video", path: "/Videos/1/original.mkv", want: true},
		{name: "emby audio", path: "/emby/Audio/1/universal", want: true},
		{name: "bare audio", path: "/Audio/1/universal", want: true},
		{name: "bare item download", path: "/Items/1/Download", want: true},
		{name: "bare item stream", path: "/Items/1/Stream", want: true},
		{name: "bare item file", path: "/Items/1/File", want: true},
		{name: "bare playback info", path: "/Items/1/PlaybackInfo", want: true},
		{name: "bare progress", path: "/Sessions/Playing/Progress", want: true},
		{name: "bare hls", path: "/Videos/1/hls1/main/0.ts", want: true},
		{name: "bare dash", path: "/Dash/manifest.mpd", want: true},
		{name: "bare smartstrm", path: "/smartstrm", want: true},
		{name: "system info", path: "/System/Info"},
		{name: "item image", path: "/Items/1/Images/Primary"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPlaybackPath(tt.path); got != tt.want {
				t.Fatalf("isPlaybackPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestAdditionalPartsPathSupportsOptionalEmbyPrefix(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "/emby/Videos/1/AdditionalParts", want: true},
		{path: "/Videos/1/AdditionalParts", want: true},
		{path: "/Items/1/AdditionalParts"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isAdditionalPartsPath(tt.path); got != tt.want {
				t.Fatalf("isAdditionalPartsPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestSTRMStreamPathSupportsOptionalEmbyPrefix(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "/emby/Videos/1/stream.strm", want: true},
		{path: "/Videos/1/stream.strm", want: true},
		{path: "/emby/Videos/1/source.strm"},
		{path: "/Movies/1/stream.strm"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := strmStreamPathRE.MatchString(tt.path); got != tt.want {
				t.Fatalf("strmStreamPathRE.MatchString(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestRawHostAllowedClassifiesDestinations(t *testing.T) {
	h := &Handler{}
	node := storage.Node{Target: "https://example.test"}
	env := config.ProxyEnv{ExternalAllowAny: true}
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "http://127.0.0.1/latest/meta-data/"},
		{raw: "http://169.254.169.254/latest/meta-data/"},
		{raw: "http://100.64.0.1/private"},
		{raw: "http://[::1]/private"},
		{raw: "http://8.8.8.8/dns-query", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			u, err := url.Parse(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.rawHostAllowed(context.Background(), node, u, env); got != tt.want {
				t.Fatalf("rawHostAllowed(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestRawIPBlockedClassifiesDestinations(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "0.0.0.1", want: true},
		{value: "100.64.0.1", want: true},
		{value: "198.18.0.1", want: true},
		{value: "192.0.2.1", want: true},
		{value: "192.31.196.1", want: true},
		{value: "192.52.193.1", want: true},
		{value: "192.175.48.1", want: true},
		{value: "198.51.100.1", want: true},
		{value: "203.0.113.1", want: true},
		{value: "240.0.0.1", want: true},
		{value: "255.255.255.255", want: true},
		{value: "64:ff9b::a00:1", want: true},
		{value: "64:ff9b:1::a00:1", want: true},
		{value: "100::1", want: true},
		{value: "2001::1", want: true},
		{value: "2001:db8::1", want: true},
		{value: "2002:a00:1::1", want: true},
		{value: "2620:4f:8000::1", want: true},
		{value: "3fff::1", want: true},
		{value: "5f00::1", want: true},
		{value: "fc00::1", want: true},
		{value: "fe80::1", want: true},
		{value: "fec0::1", want: true},
		{value: "1.1.1.1"},
		{value: "8.8.8.8"},
		{value: "2001:4860:4860::8888"},
		{value: "2606:4700:4700::1111"},
	}

	for _, tt := range tests {
		value := tt.value
		t.Run(value, func(t *testing.T) {
			ip := net.ParseIP(value)
			if ip == nil {
				t.Fatalf("net.ParseIP(%q) returned nil", value)
			}
			if got := rawIPBlocked(ip); got != tt.want {
				t.Fatalf("rawIPBlocked(%q) = %v, want %v", value, got, tt.want)
			}
		})
	}
}
