package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"embyproxy/internal/storage"
)

const identityKey = "system:upstream_identity"
const DefaultProfile = "yamby"

type Profile struct {
	Key            string
	Label          string
	ClientName     string
	ClientVersion  string
	DeviceName     string
	DeviceIDLength int
	UserAgent      string
}

type Snapshot struct {
	Profile       string `json:"profile"`
	Label         string `json:"label"`
	ClientName    string `json:"clientName"`
	ClientVersion string `json:"clientVersion"`
	DeviceName    string `json:"deviceName"`
	DeviceID      string `json:"deviceId"`
	ShortID       string `json:"shortId"`
	UserAgent     string `json:"userAgent"`
}

type deviceState struct {
	DeviceName string `json:"deviceName"`
	DeviceID   string `json:"deviceId"`
}

type persisted struct {
	ClientName    string                 `json:"clientName"`
	ClientVersion string                 `json:"clientVersion"`
	UserAgent     string                 `json:"userAgent"`
	Profiles      map[string]deviceState `json:"profiles"`
}

type Manager struct {
	store       *storage.Store
	mu          sync.Mutex
	profiles    map[string]deviceState
	initialized bool
}

var Profiles = map[string]Profile{
	"yamby": {
		Key:            "yamby",
		Label:          "Yamby Android",
		ClientName:     "Yamby",
		ClientVersion:  "2.0.4.3",
		DeviceName:     "Android",
		DeviceIDLength: 32,
		UserAgent:      "Yamby/2.0.4.3(Android",
	},
	"hills_android": {
		Key:            "hills_android",
		Label:          "Hills Android",
		ClientName:     "Hills",
		ClientVersion:  "1.7.1",
		DeviceName:     "diting",
		DeviceIDLength: 16,
		UserAgent:      "Hills/1.7.1 (android; 15)",
	},
	"hills_windows": {
		Key:            "hills_windows",
		Label:          "Hills Windows",
		ClientName:     "Hills Windows",
		ClientVersion:  "1.2.4",
		DeviceIDLength: 32,
		UserAgent:      "Hills Windows/1.2.4 (windows; 19041.vb_release.191206-1406)",
	},
}

var ProfileOrder = []string{DefaultProfile, "hills_android", "hills_windows"}

var (
	embyAuthorizationRE = regexp.MustCompile(`(?i)^(MediaBrowser|Emby)\b`)
	mediaBrowserFieldRE = map[string]*regexp.Regexp{
		"Client":   regexp.MustCompile(`(?i)\bClient\s*=\s*(?:"[^"]*"|[^,\s]+)`),
		"Device":   regexp.MustCompile(`(?i)\bDevice\s*=\s*(?:"[^"]*"|[^,\s]+)`),
		"DeviceId": regexp.MustCompile(`(?i)\bDeviceId\s*=\s*(?:"[^"]*"|[^,\s]+)`),
		"Version":  regexp.MustCompile(`(?i)\bVersion\s*=\s*(?:"[^"]*"|[^,\s]+)`),
	}
)

func NewManager(store *storage.Store) *Manager {
	return &Manager{store: store, profiles: map[string]deviceState{}}
}

func (m *Manager) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var saved persisted
	_, _ = m.store.KV().GetJSON(ctx, identityKey, &saved)
	m.profiles = normalizeSavedProfiles(saved.Profiles)
	m.initialized = true
	current := m.persistedLocked()
	if !samePersisted(saved, current) {
		return m.store.KV().Put(ctx, identityKey, current)
	}
	return nil
}

func (m *Manager) Snapshot(profile string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureLocked()
	selected := GetProfile(profile)
	state := m.deviceStateLocked(selected.Key)
	shortID := state.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return Snapshot{
		Profile:       selected.Key,
		Label:         selected.Label,
		ClientName:    selected.ClientName,
		ClientVersion: selected.ClientVersion,
		DeviceName:    state.DeviceName,
		DeviceID:      state.DeviceID,
		ShortID:       shortID,
		UserAgent:     selected.UserAgent,
	}
}

func (m *Manager) ApplyToHeaders(headers http.Header, profile string) {
	snap := m.Snapshot(profile)
	for key, values := range cloneHeader(headers) {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		switch normalizeHeaderKey(key) {
		case "xembyclient", "xmediabrowserclient":
			headers.Set(key, snap.ClientName)
		case "xembyclientversion", "xmediabrowserclientversion":
			headers.Set(key, snap.ClientVersion)
		case "xembydevicename", "xmediabrowserdevicename":
			headers.Set(key, snap.DeviceName)
		case "xembydeviceid", "xmediabrowserdeviceid":
			headers.Set(key, snap.DeviceID)
		case "xembyauthorization", "xmediabrowserauthorization", "xauthorization":
			headers.Set(key, RewriteMediaBrowserAuthorization(value, snap))
		case "xapplication":
			headers.Set(key, snap.ClientName+"/"+snap.ClientVersion)
		}
	}
	for _, key := range []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization"} {
		value := headers.Get(key)
		if value != "" && isEmbyAuthorization(value) {
			headers.Set(key, RewriteMediaBrowserAuthorization(value, snap))
		}
	}
}

func (m *Manager) ApplyToURL(u *url.URL, profile string) {
	if u == nil {
		return
	}
	snap := m.Snapshot(profile)
	q := u.Query()
	changed := false
	for key, values := range q {
		if len(values) == 0 {
			continue
		}
		switch normalizeHeaderKey(key) {
		case "xembyclient", "xmediabrowserclient":
			q.Set(key, snap.ClientName)
			changed = true
		case "xembyclientversion", "xmediabrowserclientversion":
			q.Set(key, snap.ClientVersion)
			changed = true
		case "xembydevicename", "xmediabrowserdevicename", "devicename":
			q.Set(key, snap.DeviceName)
			changed = true
		case "xembydeviceid", "xmediabrowserdeviceid", "deviceid":
			q.Set(key, snap.DeviceID)
			changed = true
		case "xembyauthorization", "xmediabrowserauthorization", "xauthorization", "authorization":
			q.Set(key, RewriteMediaBrowserAuthorization(values[0], snap))
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
}

func RewriteMediaBrowserAuthorization(value string, snap Snapshot) string {
	raw := strings.TrimSpace(value)
	if !isEmbyAuthorization(raw) {
		return value
	}
	quoted := mediaBrowserAuthValuesQuoted(snap)
	out := raw
	out = setMediaBrowserField(out, "Client", snap.ClientName, quoted)
	out = setMediaBrowserField(out, "Device", snap.DeviceName, quoted)
	out = setMediaBrowserField(out, "DeviceId", snap.DeviceID, quoted)
	out = setMediaBrowserField(out, "Version", snap.ClientVersion, quoted)
	return out
}

func isEmbyAuthorization(value string) bool {
	return embyAuthorizationRE.MatchString(strings.TrimSpace(value))
}

func NormalizeProfile(value string) string {
	key := strings.ToLower(strings.TrimSpace(value))
	if _, ok := Profiles[key]; ok {
		return key
	}
	return DefaultProfile
}

func GetProfile(value string) Profile {
	return Profiles[NormalizeProfile(value)]
}

func ProfileKeys() []string {
	seen := map[string]bool{}
	keys := make([]string, 0, len(Profiles))
	for _, key := range ProfileOrder {
		if _, ok := Profiles[key]; ok && !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	extra := make([]string, 0, len(Profiles)-len(keys))
	for key := range Profiles {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	return append(keys, extra...)
}

func (m *Manager) persistedLocked() persisted {
	current := m.SnapshotLocked(DefaultProfile)
	profiles := map[string]deviceState{}
	for key := range Profiles {
		profiles[key] = m.deviceStateLocked(key)
	}
	return persisted{
		ClientName:    current.ClientName,
		ClientVersion: current.ClientVersion,
		UserAgent:     current.UserAgent,
		Profiles:      profiles,
	}
}

func (m *Manager) SnapshotLocked(profile string) Snapshot {
	selected := GetProfile(profile)
	state := m.deviceStateLocked(selected.Key)
	shortID := state.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return Snapshot{
		Profile:       selected.Key,
		Label:         selected.Label,
		ClientName:    selected.ClientName,
		ClientVersion: selected.ClientVersion,
		DeviceName:    state.DeviceName,
		DeviceID:      state.DeviceID,
		ShortID:       shortID,
		UserAgent:     selected.UserAgent,
	}
}

func (m *Manager) ensureLocked() {
	if m.initialized && m.profiles != nil {
		return
	}
	m.profiles = normalizeSavedProfiles(m.profiles)
	m.initialized = true
}

func (m *Manager) deviceStateLocked(profile string) deviceState {
	selected := GetProfile(profile)
	if m.profiles == nil {
		m.profiles = map[string]deviceState{}
	}
	state := normalizeDeviceState(selected, m.profiles[selected.Key])
	m.profiles[selected.Key] = state
	return state
}

func normalizeSavedProfiles(saved map[string]deviceState) map[string]deviceState {
	out := map[string]deviceState{}
	for key := range Profiles {
		out[key] = normalizeDeviceState(Profiles[key], saved[key])
	}
	return out
}

func normalizeDeviceState(profile Profile, saved deviceState) deviceState {
	name := strings.TrimSpace(profile.DeviceName)
	if name == "" {
		name = strings.TrimSpace(saved.DeviceName)
	}
	if name == "" {
		name = createHillsWindowsDeviceName()
	}
	id := strings.ToLower(strings.TrimSpace(saved.DeviceID))
	if !isHexLength(id, profile.DeviceIDLength) {
		id = randomHex(profile.DeviceIDLength)
	}
	return deviceState{DeviceName: name, DeviceID: id}
}

func samePersisted(a, b persisted) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func isHexLength(value string, length int) bool {
	if length <= 0 {
		length = 32
	}
	if len(value) != length {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return true
}

func randomHex(length int) string {
	if length <= 0 {
		length = 32
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", length)
	}
	return hex.EncodeToString(buf)[:length]
}

func createHillsWindowsDeviceName() string {
	return "DESKTOP-" + strings.ToUpper(randomHex(6))
}

func setMediaBrowserField(auth, key, value string, quoted bool) string {
	re := mediaBrowserFieldRE[key]
	if re == nil {
		re = regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(key) + `\s*=\s*(?:"[^"]*"|[^,\s]+)`)
	}
	if loc := re.FindStringIndex(auth); loc != nil {
		return auth[:loc[0]] + key + "=" + formatMediaBrowserValue(value, quoted) + auth[loc[1]:]
	}
	return strings.TrimRight(auth, " \t\r\n") + `, ` + key + "=" + formatMediaBrowserValue(value, quoted)
}

func formatMediaBrowserValue(value string, quoted bool) string {
	if quoted {
		return `"` + escapeMediaBrowserValue(value) + `"`
	}
	return value
}

func escapeMediaBrowserValue(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`)
}

func mediaBrowserAuthValuesQuoted(snap Snapshot) bool {
	profile := NormalizeProfile(snap.Profile)
	if snap.Profile == "" {
		profile = strings.ToLower(strings.TrimSpace(snap.ClientName))
	}
	return strings.HasPrefix(profile, "hills")
}

func normalizeHeaderKey(value string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(value))
}

func cloneHeader(in http.Header) http.Header {
	out := http.Header{}
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
