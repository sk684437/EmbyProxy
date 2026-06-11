package identity

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRewriteMediaBrowserAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		snap    Snapshot
		wants   []string
		rejects []string
	}{
		{
			name: "yamby unquotes fields",
			raw:  `Emby UserId=user,Client="Synthetic Client",Device="SYNTHETIC-PC",DeviceId="synthetic-source-device-id",Version="1.0"`,
			snap: Snapshot{
				Profile:       DefaultProfile,
				ClientName:    "Yamby",
				ClientVersion: "2.0.4.3",
				DeviceName:    "Android",
				DeviceID:      "synthetic-yamby-device-id",
			},
			wants:   []string{`Client=Yamby`, `Device=Android`, `DeviceId=synthetic-yamby-device-id`, `Version=2.0.4.3`},
			rejects: []string{"Synthetic Client", "SYNTHETIC-PC", "synthetic-source-device-id"},
		},
		{
			name: "hills windows quotes fields",
			raw:  `Emby Client=Original, Device=HOME-PC, DeviceId=original, Version=1.0`,
			snap: Snapshot{
				Profile:       "hills_windows",
				ClientName:    "Hills Windows",
				ClientVersion: "1.2.4",
				DeviceName:    "DESKTOP-TEST",
				DeviceID:      "synthetic-hills-device-id",
			},
			wants: []string{`Client="Hills Windows"`, `Device="DESKTOP-TEST"`, `DeviceId="synthetic-hills-device-id"`, `Version="1.2.4"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RewriteMediaBrowserAuthorization(tt.raw, tt.snap)
			for _, want := range tt.wants {
				if !strings.Contains(got, want) {
					t.Fatalf("rewritten authorization missing %s: %s", want, got)
				}
			}
			for _, reject := range tt.rejects {
				if strings.Contains(got, reject) {
					t.Fatalf("rewritten authorization still contains %s: %s", reject, got)
				}
			}
		})
	}
}

func TestApplyToHeadersRewritesEmbyAuthorization(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	headers.Set("Authorization", `Emby Client="Synthetic Client", Device="SYNTHETIC-PC", DeviceId="synthetic-source-device-id", Version="1.2.0"`)
	headers.Set("X-Emby-Authorization", `Emby Client="Synthetic Client", Device="SYNTHETIC-PC", DeviceId="synthetic-source-device-id", Version="1.2.0"`)

	manager.ApplyToHeaders(headers, "yamby")

	for _, key := range []string{"Authorization", "X-Emby-Authorization"} {
		value := headers.Get(key)
		if !strings.Contains(value, `Client=Yamby`) || !strings.Contains(value, `Device=Android`) {
			t.Fatalf("%s was not rewritten to yamby identity: %s", key, value)
		}
	}
}

func TestApplyToHeadersDoesNotAddMissingEmbyHeaders(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}

	manager.ApplyToHeaders(headers, "yamby")

	for _, key := range []string{"Authorization", "X-Emby-Authorization", "X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Name", "X-Emby-Device-Id"} {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want empty", key, got)
		}
	}
}

func TestApplyToURLRewritesEmbyAuthorization(t *testing.T) {
	manager := NewManager(nil)
	u, err := url.Parse(`https://example.test/emby/Users/1?X-Emby-Authorization=Emby+Client%3D%22Synthetic+Client%22%2C+Device%3D%22SYNTHETIC-PC%22%2C+DeviceId%3D%22synthetic-source-device-id%22%2C+Version%3D%221.2.0%22`)
	if err != nil {
		t.Fatal(err)
	}

	manager.ApplyToURL(u, "yamby")

	value := u.Query().Get("X-Emby-Authorization")
	if !strings.Contains(value, `Client=Yamby`) || !strings.Contains(value, `Device=Android`) {
		t.Fatalf("URL authorization was not rewritten to yamby identity: %s", value)
	}
}
