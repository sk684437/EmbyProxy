package identity

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	testYambyDeviceID  = "00000000-0000-4000-8000-000000000001"
	testHillsWindowsID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHillsAndroidID = "bbbbbbbbbbbbbbbb"
	testSourceAuth     = `MediaBrowser Token="source-token", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
	testSourceEmbyAuth = `Emby UserId="source-user", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
)

func TestRewriteMediaBrowserAuthorization(t *testing.T) {
	yamby := Snapshot{
		Profile:       DefaultProfile,
		ClientName:    "Yamby",
		ClientVersion: "2.0.4.3",
		DeviceName:    "Android",
		DeviceID:      testYambyDeviceID,
	}
	hillsWindows := Snapshot{
		Profile:       "hills_windows",
		ClientName:    "Hills Windows",
		ClientVersion: "1.2.4",
		DeviceName:    "DESKTOP-TEST",
		DeviceID:      testHillsWindowsID,
	}
	hillsAndroid := Snapshot{
		Profile:       "hills_android",
		ClientName:    "Hills",
		ClientVersion: "1.7.1",
		DeviceName:    "diting",
		DeviceID:      testHillsAndroidID,
	}
	tests := []struct {
		name string
		raw  string
		snap Snapshot
		want string
	}{
		{
			name: "yamby rewrites emby auth without user id field",
			raw:  `Emby UserId=user-from-auth,Client="Source Client",Device="Source Device",DeviceId="source-device-id",Version="0.0.0-test"`,
			snap: yamby,
			want: `Emby Client=Yamby,Device=Android,DeviceId=` + testYambyDeviceID + `,Version=2.0.4.3`,
		},
		{
			name: "yamby rewrites media browser auth without token field",
			raw:  testSourceAuth,
			snap: yamby,
			want: `Emby Client=Yamby,Device=Android,DeviceId=` + testYambyDeviceID + `,Version=2.0.4.3`,
		},
		{
			name: "keeps non emby bearer authorization",
			raw:  `Bearer Token="source-token"`,
			snap: yamby,
			want: `Bearer Token="source-token"`,
		},
		{
			name: "keeps emby prefix lookalike",
			raw:  `EmbyX Client=Original, Device=SOURCE-PC`,
			snap: yamby,
			want: `EmbyX Client=Original, Device=SOURCE-PC`,
		},
		{
			name: "hills windows keeps quoted fields",
			raw:  `Emby Client=Original, Device=SOURCE-PC, DeviceId=original, Version=1.0`,
			snap: hillsWindows,
			want: `Emby Client="Hills Windows", Device="DESKTOP-TEST", DeviceId="` + testHillsWindowsID + `", Version="1.2.4"`,
		},
		{
			name: "hills android rewrites media browser auth without token field",
			raw:  testSourceAuth,
			snap: hillsAndroid,
			want: `Emby Client="Hills", Device="diting", DeviceId="` + testHillsAndroidID + `", Version="1.7.1"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RewriteMediaBrowserAuthorization(tt.raw, tt.snap); got != tt.want {
				t.Fatalf("RewriteMediaBrowserAuthorization() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyToHeadersMovesMediaBrowserToken(t *testing.T) {
	tests := []struct {
		name              string
		headers           http.Header
		wantToken         string
		wantAuthRewritten bool
		wantAuthorization string
	}{
		{
			name:              "moves media browser token when token header is missing",
			wantAuthRewritten: true,
			headers: http.Header{
				"X-Emby-Authorization": {testSourceAuth},
			},
			wantToken: "source-token",
		},
		{
			name:              "preserves existing token header",
			wantAuthRewritten: true,
			headers: http.Header{
				"X-Emby-Authorization": {testSourceAuth},
				"X-Emby-Token":         {"existing-token"},
			},
			wantToken: "existing-token",
		},
		{
			name: "ignores token field without media browser scheme",
			headers: http.Header{
				"Authorization": {`Token="source-token"`},
			},
			wantToken:         "",
			wantAuthorization: `Token="source-token"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(nil)
			snap := manager.Snapshot(DefaultProfile)
			wantAuth := "Emby Client=" + snap.ClientName + ",Device=" + snap.DeviceName + ",DeviceId=" + snap.DeviceID + ",Version=" + snap.ClientVersion

			manager.ApplyToHeaders(tt.headers, DefaultProfile)

			if got := tt.headers.Get("X-Emby-Token"); got != tt.wantToken {
				t.Fatalf("X-Emby-Token = %q, want %q", got, tt.wantToken)
			}
			if got := tt.headers.Get("X-Emby-Authorization"); tt.wantAuthRewritten && got != wantAuth {
				t.Fatalf("X-Emby-Authorization = %q, want %q", got, wantAuth)
			} else if !tt.wantAuthRewritten && got != "" {
				t.Fatalf("X-Emby-Authorization = %q, want empty", got)
			}
			if strings.Contains(strings.ToLower(tt.headers.Get("X-Emby-Authorization")), "token=") {
				t.Fatalf("X-Emby-Authorization still contains token: %q", tt.headers.Get("X-Emby-Authorization"))
			}
			if got := tt.headers.Get("Authorization"); tt.wantAuthorization != "" && got != tt.wantAuthorization {
				t.Fatalf("Authorization = %q, want %q", got, tt.wantAuthorization)
			}
		})
	}
}

func TestApplyToHeadersRewritesEmbyAuthorization(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	headers.Set("Authorization", testSourceEmbyAuth)
	headers.Set("X-Emby-Authorization", testSourceEmbyAuth)
	headers.Set("X-Application", "Original/1.0")

	manager.ApplyToHeaders(headers, "yamby")

	for _, key := range []string{"Authorization", "X-Emby-Authorization"} {
		value := headers.Get(key)
		if !strings.Contains(value, `Client=Yamby`) || !strings.Contains(value, `Device=Android`) {
			t.Fatalf("%s was not rewritten to yamby identity: %s", key, value)
		}
	}
	if got := headers.Get("X-Application"); got != "Yamby/2.0.4.3" {
		t.Fatalf("X-Application = %q, want %q", got, "Yamby/2.0.4.3")
	}
}

func TestApplyToHeadersDoesNotAddMissingEmbyHeaders(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}

	manager.ApplyToHeaders(headers, "yamby")

	for _, key := range []string{"Authorization", "X-Application", "X-Emby-Authorization", "X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Name", "X-Emby-Device-Id"} {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want empty", key, got)
		}
	}
}

func TestApplyToURLMatchesProfileQueryIdentityBehavior(t *testing.T) {
	manager := NewManager(nil)
	yamby := manager.Snapshot("yamby")
	hillsWindows := manager.Snapshot("hills_windows")
	tests := []struct {
		name      string
		profile   string
		want      []string
		wantQuery map[string]string
		reject    []string
	}{
		{
			name:    "yamby rewrites existing query identity",
			profile: "yamby",
			want:    []string{"X-Emby-Authorization=", "Client%3DYamby", "Device%3DAndroid", "X-Emby-Client=Yamby"},
			wantQuery: map[string]string{
				"X-Emby-Token":          "token",
				"X-Emby-Client":         "Yamby",
				"X-Emby-Client-Version": "2.0.4.3",
				"X-Emby-Device-Name":    "Android",
				"X-Emby-Device-Id":      yamby.DeviceID,
			},
			reject: []string{"Synthetic+Client", "SYNTHETIC-PC"},
		},
		{
			name:    "hills windows rewrites query identity",
			profile: "hills_windows",
			want:    []string{"X-Emby-Authorization=", "Client%3D%22Hills+Windows%22", "X-Emby-Client=Hills+Windows"},
			wantQuery: map[string]string{
				"X-Emby-Device-Name": hillsWindows.DeviceName,
				"X-Emby-Device-Id":   hillsWindows.DeviceID,
			},
			reject: []string{"Synthetic+Client", "SYNTHETIC-PC"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(`https://example.test/emby/Users/1?X-Emby-Authorization=Emby+Client%3D%22Synthetic+Client%22%2C+Device%3D%22SYNTHETIC-PC%22%2C+DeviceId%3D%22synthetic-source-device-id%22%2C+Version%3D%221.2.0%22&X-Emby-Client=Synthetic+Client&X-Emby-Client-Version=1.2.0&X-Emby-Device-Name=SYNTHETIC-PC&X-Emby-Device-Id=synthetic-source-device-id&X-Emby-Token=token&tag=v1`)
			if err != nil {
				t.Fatal(err)
			}

			manager.ApplyToURL(u, tt.profile)

			got := u.RawQuery
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("RawQuery = %q, want to contain %q", got, want)
				}
			}
			for _, reject := range tt.reject {
				if strings.Contains(got, reject) {
					t.Fatalf("RawQuery = %q, want to reject %q", got, reject)
				}
			}
			query := u.Query()
			for key, want := range tt.wantQuery {
				if got := query.Get(key); got != want {
					t.Fatalf("%s = %q, want %q", key, got, want)
				}
			}
			if !strings.Contains(got, "tag=v1") {
				t.Fatalf("RawQuery = %q, want to preserve non-identity query", got)
			}
		})
	}
}

func TestProfileDeviceIdentityDefaults(t *testing.T) {
	manager := NewManager(nil)
	tests := []struct {
		name       string
		profile    string
		deviceName string
		idLength   int
		idFormat   string
	}{
		{
			name:       "yamby keeps original android strategy",
			profile:    "yamby",
			deviceName: "Android",
			idFormat:   "uuid",
		},
		{
			name:       "hills android keeps original diting strategy",
			profile:    "hills_android",
			deviceName: "diting",
			idLength:   16,
		},
		{
			name:     "hills windows keeps generated desktop strategy",
			profile:  "hills_windows",
			idLength: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := manager.Snapshot(tt.profile)
			if tt.deviceName != "" && snap.DeviceName != tt.deviceName {
				t.Fatalf("DeviceName = %q, want %q", snap.DeviceName, tt.deviceName)
			}
			if tt.profile == "hills_windows" && !strings.HasPrefix(snap.DeviceName, "DESKTOP-") {
				t.Fatalf("DeviceName = %q, want DESKTOP-*", snap.DeviceName)
			}
			switch tt.idFormat {
			case "uuid":
				if !isUUID(snap.DeviceID) {
					t.Fatalf("DeviceID = %q, want uuid", snap.DeviceID)
				}
			default:
				if !isHexLength(snap.DeviceID, tt.idLength) {
					t.Fatalf("DeviceID = %q, want %d hex chars", snap.DeviceID, tt.idLength)
				}
			}
		})
	}
}
