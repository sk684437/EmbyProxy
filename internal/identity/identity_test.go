package identity

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	testYambyDeviceID          = "00000000-0000-4000-8000-000000000001"
	testHillsWindowsID         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHillsAndroidID         = "bbbbbbbbbbbbbbbb"
	testSourceMediaBrowserAuth = `MediaBrowser Token="source-token", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
	testSourceEmbyTokenAuth    = `Emby Token="source-token", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
	testSourceEmbyAuth         = `Emby UserId="source-user", Client="Source Client", Device="Source Device", DeviceId="source-device-id", Version="0.0.0-test"`
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
			raw:  testSourceMediaBrowserAuth,
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
			raw:  testSourceMediaBrowserAuth,
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

func TestApplyToHeadersMovesAuthorizationToken(t *testing.T) {
	tests := []struct {
		name                 string
		headers              http.Header
		wantToken            string
		wantRewrittenAuthKey string
		wantAuthorization    string
	}{
		{
			name:                 "moves MediaBrowser token when token header is missing",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"X-Emby-Authorization": {testSourceMediaBrowserAuth},
			},
			wantToken: "source-token",
		},
		{
			name:                 "moves Emby token when token header is missing",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"X-Emby-Authorization": {testSourceEmbyTokenAuth},
			},
			wantToken: "source-token",
		},
		{
			name:                 "moves X-Authorization token when token header is missing",
			wantRewrittenAuthKey: "X-Authorization",
			headers: http.Header{
				"X-Authorization": {testSourceEmbyTokenAuth},
			},
			wantToken: "source-token",
		},
		{
			name:                 "preserves existing token header",
			wantRewrittenAuthKey: "X-Emby-Authorization",
			headers: http.Header{
				"X-Emby-Authorization": {testSourceMediaBrowserAuth},
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
			if tt.wantRewrittenAuthKey != "" {
				value := tt.headers.Get(tt.wantRewrittenAuthKey)
				if value != wantAuth {
					t.Fatalf("%s = %q, want %q", tt.wantRewrittenAuthKey, value, wantAuth)
				}
				if strings.Contains(strings.ToLower(value), "token=") {
					t.Fatalf("%s still contains token: %q", tt.wantRewrittenAuthKey, value)
				}
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
	headers.Set("X-Emby-Token", "kept-token")
	headers.Set("X-Emby-Client", "Original")
	headers.Set("X-Emby-Client-Version", "1.0")
	headers.Set("X-Emby-Device-Id", "original-device")
	headers.Set("X-Emby-Device-Name", "Original Device")
	headers.Set("X-MediaBrowser-Client", "Original")
	headers.Set("X-MediaBrowser-Client-Version", "1.0")
	headers.Set("X-MediaBrowser-Device-Id", "original-device")
	headers.Set("X-MediaBrowser-Device-Name", "Original Device")

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
	for _, key := range []string{
		"X-Emby-Client", "X-Emby-Client-Version", "X-Emby-Device-Id", "X-Emby-Device-Name",
		"X-MediaBrowser-Client", "X-MediaBrowser-Client-Version", "X-MediaBrowser-Device-Id", "X-MediaBrowser-Device-Name",
	} {
		if got := headers.Get(key); got != "" {
			t.Fatalf("%s = %q, want dropped for yamby impersonation", key, got)
		}
	}
	if got := headers.Get("X-Emby-Token"); got != "kept-token" {
		t.Fatalf("X-Emby-Token = %q, want retained", got)
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

func TestApplyToHeadersKeepsIdentityHeadersForHillsWindows(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	headers.Set("X-Emby-Client", "Original")
	headers.Set("X-Emby-Device-Id", "original-device")

	manager.ApplyToHeaders(headers, "hills_windows")

	if got := headers.Get("X-Emby-Client"); got != "Hills Windows" {
		t.Fatalf("X-Emby-Client = %q, want rewritten identity (not dropped)", got)
	}
}

func TestApplyToURLMigratesYambyAllowedQueryAuth(t *testing.T) {
	manager := NewManager(nil)
	tests := []struct {
		queryKey string
		header   string
	}{
		{queryKey: "authorization", header: "Authorization"},
		{queryKey: "x-authorization", header: "X-Authorization"},
		{queryKey: "x-emby-authorization", header: "X-Emby-Authorization"},
		{queryKey: "x-emby-token", header: "X-Emby-Token"},
		{queryKey: "x-mediabrowser-authorization", header: "X-MediaBrowser-Authorization"},
		{queryKey: "x-mediabrowser-token", header: "X-MediaBrowser-Token"},
		{queryKey: "X_eMbY_ToKeN", header: "X-Emby-Token"},
	}

	for _, tt := range tests {
		t.Run(tt.queryKey, func(t *testing.T) {
			headers := http.Header{}
			u := parseIdentityURL(t, tt.queryKey+"=query-value&tag=v1")

			manager.ApplyToURL(u, headers, "yamby")

			query := u.Query()
			if headers.Get(tt.header) != "query-value" {
				t.Fatalf("%s header behavior did not match expectation", tt.header)
			}
			if query.Has(tt.queryKey) {
				t.Fatalf("%s query was not removed", tt.queryKey)
			}
			if got := query.Get("tag"); got != "v1" {
				t.Fatal("ordinary query parameter was not preserved")
			}
		})
	}
}

func TestApplyToURLUsesFirstYambyQueryAuthValue(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	u := parseIdentityURL(t, "x-emby-token=first-value&x-emby-token=second-value")

	manager.ApplyToURL(u, headers, "yamby")

	if headers.Get("X-Emby-Token") != "first-value" {
		t.Fatal("X-Emby-Token header behavior did not match expectation")
	}
	if u.Query().Has("x-emby-token") {
		t.Fatal("x-emby-token query was not removed")
	}
}

func TestApplyToURLKeepsExistingYambyHeader(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{"X-Emby-Token": {"header-value"}}
	u := parseIdentityURL(t, "x-emby-token=query-value")

	manager.ApplyToURL(u, headers, "yamby")

	if headers.Get("X-Emby-Token") != "header-value" {
		t.Fatal("existing X-Emby-Token header was overwritten")
	}
	if u.Query().Has("x-emby-token") {
		t.Fatal("x-emby-token query was not removed")
	}
}

func TestApplyToURLFillsEmptyExistingYambyHeader(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{"X-Emby-Token": {""}}
	u := parseIdentityURL(t, "x-emby-token=query-value")

	manager.ApplyToURL(u, headers, "yamby")

	if headers.Get("X-Emby-Token") != "query-value" {
		t.Fatal("empty X-Emby-Token header was not filled from query")
	}
	if u.Query().Has("x-emby-token") {
		t.Fatal("x-emby-token query was not removed")
	}
}

func TestApplyToURLMovesQueryAuthorizationToken(t *testing.T) {
	manager := NewManager(nil)
	encodedAuth := url.QueryEscape(testSourceEmbyTokenAuth)
	tests := []struct {
		name              string
		profile           string
		rawQuery          string
		headers           http.Header
		wantToken         string
		wantRemovedQuery  []string
		wantNoQueryToken  bool
		wantOrdinaryQuery bool
	}{
		{name: "yamby", profile: "yamby", rawQuery: "X-Emby-Authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantRemovedQuery: []string{"X-Emby-Authorization"}, wantOrdinaryQuery: true},
		{name: "yamby x authorization alias", profile: "yamby", rawQuery: "x-authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantRemovedQuery: []string{"x-authorization"}, wantOrdinaryQuery: true},
		{name: "hills android", profile: "hills_android", rawQuery: "X-Emby-Authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantNoQueryToken: true, wantOrdinaryQuery: true},
		{name: "hills windows", profile: "hills_windows", rawQuery: "X-Emby-Authorization=" + encodedAuth + "&tag=v1", headers: http.Header{}, wantToken: "source-token", wantNoQueryToken: true, wantOrdinaryQuery: true},
		{name: "existing header token wins", profile: "hills_windows", rawQuery: "X-Emby-Authorization=" + encodedAuth, headers: http.Header{"X-Emby-Token": {"existing-token"}}, wantToken: "existing-token", wantNoQueryToken: true},
		{name: "yamby query token wins", profile: "yamby", rawQuery: "x-emby-token=query-token&X-Emby-Authorization=" + encodedAuth, headers: http.Header{}, wantToken: "query-token", wantRemovedQuery: []string{"x-emby-token", "X-Emby-Authorization"}},
		{name: "bare token ignored", profile: "hills_windows", rawQuery: "X-Emby-Authorization=" + url.QueryEscape(`Token="source-token"`), headers: http.Header{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := parseIdentityURL(t, tt.rawQuery)

			manager.ApplyToURL(u, tt.headers, tt.profile)

			if got := tt.headers.Get("X-Emby-Token"); got != tt.wantToken {
				t.Fatalf("X-Emby-Token = %q, want %q", got, tt.wantToken)
			}
			query := u.Query()
			for _, key := range tt.wantRemovedQuery {
				if query.Has(key) {
					t.Fatalf("%s query was not removed: %s", key, u.RawQuery)
				}
			}
			if tt.wantNoQueryToken && strings.Contains(strings.ToLower(query.Get("X-Emby-Authorization")), "token=") {
				t.Fatalf("query X-Emby-Authorization still contains token: %q", query.Get("X-Emby-Authorization"))
			}
			if tt.wantOrdinaryQuery && query.Get("tag") != "v1" {
				t.Fatalf("tag = %q, want v1", query.Get("tag"))
			}
		})
	}
}

func TestApplyToURLStripsOtherYambyIdentityQueryAndKeepsOrdinaryQuery(t *testing.T) {
	manager := NewManager(nil)
	headers := http.Header{}
	u := parseIdentityURL(t, "x-emby-client=Client&x-emby-device-id=device&x-mediabrowser-client=MediaBrowser&x-mediabrowser-device-id=media-device&X_MediaBrowser_Client_Version=1.2.3&DeviceId=source-device&DeviceName=source-name&quality=90&tag=v1&fields=Overview&maxwidth=600&api_key=api-value&playsessionid=session-value")

	manager.ApplyToURL(u, headers, "yamby")

	query := u.Query()
	for _, key := range []string{"x-emby-client", "x-emby-device-id", "x-mediabrowser-client", "x-mediabrowser-device-id", "X_MediaBrowser_Client_Version", "DeviceId", "DeviceName"} {
		if query.Has(key) {
			t.Fatalf("%s query was not removed", key)
		}
	}
	for _, key := range []string{"X-Emby-Client", "X-Emby-Device-Id", "X-MediaBrowser-Client", "X-MediaBrowser-Device-Id", "X-MediaBrowser-Client-Version"} {
		if headers.Get(key) != "" {
			t.Fatalf("%s header should not be set", key)
		}
	}
	for key, want := range map[string]string{
		"quality":       "90",
		"tag":           "v1",
		"fields":        "Overview",
		"maxwidth":      "600",
		"api_key":       "api-value",
		"playsessionid": "session-value",
	} {
		if query.Get(key) != want {
			t.Fatalf("%s query behavior did not match expectation", key)
		}
	}
}

func TestApplyToURLStripsControlBytesFromPromotedHeaderValues(t *testing.T) {
	manager := NewManager(nil)

	t.Run("yamby query auth header value", func(t *testing.T) {
		headers := http.Header{}
		// Authorization value decoded contains CR/LF and a NUL byte.
		u := parseIdentityURL(t, "Authorization="+url.QueryEscape("Emby\r\nX-Injected: 1\r\nClient=Yamby\x00"))

		manager.ApplyToURL(u, headers, "yamby")

		got := headers.Get("Authorization")
		if strings.ContainsAny(got, "\r\n\x00") {
			t.Fatalf("promoted Authorization still carries control bytes: %q", got)
		}
		if !strings.Contains(got, "Client=Yamby") {
			t.Fatalf("promoted Authorization dropped valid content: %q", got)
		}
	})

	t.Run("yamby query token header value", func(t *testing.T) {
		headers := http.Header{}
		// The token field's quoted value contains an embedded CR/LF.
		auth := `Emby Token="evil` + "\r\n" + `tail"`
		u := parseIdentityURL(t, "X-Emby-Authorization="+url.QueryEscape(auth))

		manager.ApplyToURL(u, headers, "yamby")

		got := headers.Get("X-Emby-Token")
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("promoted X-Emby-Token still carries control bytes: %q", got)
		}
		if got == "" {
			t.Fatalf("X-Emby-Token was not promoted")
		}
	})

	t.Run("hills query token header value", func(t *testing.T) {
		headers := http.Header{}
		auth := `Emby Token="evil` + "\r\n" + `tail"`
		u := parseIdentityURL(t, "X-Emby-Authorization="+url.QueryEscape(auth))

		manager.ApplyToURL(u, headers, "hills_windows")

		got := headers.Get("X-Emby-Token")
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("promoted X-Emby-Token still carries control bytes: %q", got)
		}
		if got == "" {
			t.Fatalf("X-Emby-Token was not promoted")
		}
	})
}

func TestApplyToURLKeepsHillsQueryIdentityBehavior(t *testing.T) {
	manager := NewManager(nil)
	hillsWindows := manager.Snapshot("hills_windows")
	u, err := url.Parse(`https://example.test/emby/Users/1?X-Emby-Authorization=Emby+Client%3D%22Synthetic+Client%22%2C+Device%3D%22SYNTHETIC-PC%22%2C+DeviceId%3D%22synthetic-source-device-id%22%2C+Version%3D%221.2.0%22&X-Emby-Client=Synthetic+Client&X-Emby-Device-Name=SYNTHETIC-PC&X-Emby-Device-Id=synthetic-source-device-id&tag=v1`)
	if err != nil {
		t.Fatal(err)
	}

	manager.ApplyToURL(u, http.Header{}, "hills_windows")

	got := u.RawQuery
	for _, want := range []string{"X-Emby-Authorization=", "Client%3D%22Hills+Windows%22", "X-Emby-Client=Hills+Windows"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RawQuery = %q, want to contain %q", got, want)
		}
	}
	for _, reject := range []string{"Synthetic+Client", "SYNTHETIC-PC"} {
		if strings.Contains(got, reject) {
			t.Fatalf("RawQuery = %q, want to reject %q", got, reject)
		}
	}
	query := u.Query()
	for key, want := range map[string]string{
		"X-Emby-Device-Name": hillsWindows.DeviceName,
		"X-Emby-Device-Id":   hillsWindows.DeviceID,
	} {
		if got := query.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if !strings.Contains(got, "tag=v1") {
		t.Fatalf("RawQuery = %q, want to preserve non-identity query", got)
	}
}

func parseIdentityURL(t *testing.T, rawQuery string) *url.URL {
	t.Helper()
	u, err := url.Parse("https://example.test/emby/Users/1?" + rawQuery)
	if err != nil {
		t.Fatal(err)
	}
	return u
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
