package identity

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRewriteMediaBrowserAuthorizationSupportsEmbyPrefix(t *testing.T) {
	snap := Snapshot{
		ClientName:    "Yamby",
		ClientVersion: "2.0.3.4",
		DeviceName:    "Android",
		DeviceID:      "synthetic-yamby-device-id",
	}
	raw := `Emby Client="Synthetic Client", Device="SYNTHETIC-PC", DeviceId="synthetic-source-device-id", Version="1.2.0"`

	got := RewriteMediaBrowserAuthorization(raw, snap)

	for _, want := range []string{`Client="Yamby"`, `Device="Android"`, `DeviceId="synthetic-yamby-device-id"`, `Version="2.0.3.4"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten authorization missing %s: %s", want, got)
		}
	}
	if strings.Contains(got, "Synthetic Client") || strings.Contains(got, "SYNTHETIC-PC") || strings.Contains(got, "synthetic-source-device-id") {
		t.Fatalf("rewritten authorization still contains original identity: %s", got)
	}
}

func TestApplyToHeadersRewritesEmbyAuthorization(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	headers.Set("Authorization", `Emby Client="Synthetic Client", Device="SYNTHETIC-PC", DeviceId="synthetic-source-device-id", Version="1.2.0"`)
	headers.Set("X-Emby-Authorization", `Emby Client="Synthetic Client", Device="SYNTHETIC-PC", DeviceId="synthetic-source-device-id", Version="1.2.0"`)

	manager.ApplyToHeaders(headers, "yamby", true)

	for _, key := range []string{"Authorization", "X-Emby-Authorization"} {
		value := headers.Get(key)
		if !strings.Contains(value, `Client="Yamby"`) || !strings.Contains(value, `Device="Android"`) {
			t.Fatalf("%s was not rewritten to yamby identity: %s", key, value)
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
	if !strings.Contains(value, `Client="Yamby"`) || !strings.Contains(value, `Device="Android"`) {
		t.Fatalf("URL authorization was not rewritten to yamby identity: %s", value)
	}
}
