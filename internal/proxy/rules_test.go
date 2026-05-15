package proxy

import (
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
