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
	DeviceIDFormat string
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
		DeviceIDFormat: "uuid",
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
	embyAuthorizationRE = regexp.MustCompile(`(?i)^(?:MediaBrowser|Emby)(?:\s|$)`)
	mediaBrowserTokenRE = regexp.MustCompile(`(?i)^MediaBrowser(?:\s|$).*?\bToken\s*=\s*("[^"]*"|[^,\s]+)`)
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
	if headers.Get("X-Emby-Token") == "" {
		if token := authTokenFromHeaders(headers); token != "" {
			headers.Set("X-Emby-Token", token)
		}
	}
	dropIdentityHeaders := usesYambyAuthFormat(snap)
	for key, values := range cloneHeader(headers) {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		switch normalizeHeaderKey(key) {
		case "xembyclient", "xmediabrowserclient":
			setOrDropIdentityHeader(headers, key, snap.ClientName, dropIdentityHeaders)
		case "xembyclientversion", "xmediabrowserclientversion":
			setOrDropIdentityHeader(headers, key, snap.ClientVersion, dropIdentityHeaders)
		case "xembydevicename", "xmediabrowserdevicename":
			setOrDropIdentityHeader(headers, key, snap.DeviceName, dropIdentityHeaders)
		case "xembydeviceid", "xmediabrowserdeviceid":
			setOrDropIdentityHeader(headers, key, snap.DeviceID, dropIdentityHeaders)
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

// setOrDropIdentityHeader rewrites a standalone client/device identity header,
// or drops it when drop is set. For yamby upstreams these headers are redundant
// (the values already live in the Emby authorization string) and are dropped
// instead of forwarded.
func setOrDropIdentityHeader(headers http.Header, key, value string, drop bool) {
	if drop {
		headers.Del(key)
		return
	}
	headers.Set(key, value)
}

func (m *Manager) ApplyToURL(u *url.URL, headers http.Header, profile string) {
	if u == nil {
		return
	}
	snap := m.Snapshot(profile)
	if usesYambyAuthFormat(snap) {
		applyYambyQueryAuthToHeaders(u, headers)
		return
	}
	applyProfileIdentityToURL(u, snap)
}

func applyProfileIdentityToURL(u *url.URL, snap Snapshot) {
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

var yambyQueryAuthHeaders = map[string]string{
	"authorization":              "Authorization",
	"xauthorization":             "X-Authorization",
	"xembyauthorization":         "X-Emby-Authorization",
	"xembytoken":                 "X-Emby-Token",
	"xmediabrowserauthorization": "X-MediaBrowser-Authorization",
	"xmediabrowsertoken":         "X-MediaBrowser-Token",
}

func applyYambyQueryAuthToHeaders(u *url.URL, headers http.Header) {
	q := u.Query()
	changed := false

	for rawQuery := u.RawQuery; rawQuery != ""; {
		var part string
		part, rawQuery, _ = strings.Cut(rawQuery, "&")
		if part == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		normalizedKey := normalizeHeaderKey(key)
		if canonical, ok := yambyQueryAuthHeaders[normalizedKey]; ok {
			if headers != nil && !headersHaveNonEmptyValue(headers, canonical) {
				value, err := url.QueryUnescape(rawValue)
				if err != nil {
					value = rawValue
				}
				headers.Set(canonical, value)
			}
			q.Del(key)
			changed = true
			continue
		}
		if isYambyQueryIdentityKey(normalizedKey) {
			q.Del(key)
			changed = true
		}
	}

	if changed {
		u.RawQuery = q.Encode()
	}
}

func isYambyQueryIdentityKey(normalizedKey string) bool {
	if strings.HasPrefix(normalizedKey, "xemby") || strings.HasPrefix(normalizedKey, "xmediabrowser") {
		return true
	}
	switch normalizedKey {
	case "deviceid", "devicename":
		return true
	default:
		return false
	}
}

func headersHaveNonEmptyValue(headers http.Header, canonical string) bool {
	for key := range headers {
		if strings.EqualFold(key, canonical) {
			for _, value := range headers[key] {
				if strings.TrimSpace(value) != "" {
					return true
				}
			}
		}
	}
	return false
}

func RewriteMediaBrowserAuthorization(value string, snap Snapshot) string {
	raw := strings.TrimSpace(value)
	if !isEmbyAuthorization(raw) {
		return value
	}
	if usesYambyAuthFormat(snap) {
		return buildYambyAuthorization(raw, snap)
	}
	return buildHillsAuthorization(snap)
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
	deviceID := strings.ToLower(strings.TrimSpace(saved.DeviceID))
	if !validDeviceID(profile, deviceID) {
		deviceID = randomDeviceID(profile)
	}
	return deviceState{DeviceName: name, DeviceID: deviceID}
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

func validDeviceID(profile Profile, value string) bool {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return isUUID(value)
	default:
		return isHexLength(value, profile.DeviceIDLength)
	}
}

func randomDeviceID(profile Profile) string {
	switch strings.ToLower(strings.TrimSpace(profile.DeviceIDFormat)) {
	case "uuid":
		return randomUUID()
	default:
		return randomHex(profile.DeviceIDLength)
	}
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

func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
				continue
			}
			return false
		}
	}
	return true
}

func randomUUID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	hexed := hex.EncodeToString(buf)
	return hexed[:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:]
}

func createHillsWindowsDeviceName() string {
	return "DESKTOP-" + strings.ToUpper(randomHex(6))
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

func usesYambyAuthFormat(snap Snapshot) bool {
	profile := NormalizeProfile(snap.Profile)
	if snap.Profile == "" {
		profile = strings.ToLower(strings.TrimSpace(snap.ClientName))
	}
	return profile == DefaultProfile
}

func buildYambyAuthorization(_ string, snap Snapshot) string {
	parts := []string{
		"Client=" + snap.ClientName,
		"Device=" + snap.DeviceName,
		"DeviceId=" + snap.DeviceID,
		"Version=" + snap.ClientVersion,
	}
	return "Emby " + strings.Join(parts, ",")
}

func buildHillsAuthorization(snap Snapshot) string {
	parts := []string{
		"Client=" + formatMediaBrowserValue(snap.ClientName, true),
		"Device=" + formatMediaBrowserValue(snap.DeviceName, true),
		"DeviceId=" + formatMediaBrowserValue(snap.DeviceID, true),
		"Version=" + formatMediaBrowserValue(snap.ClientVersion, true),
	}
	return "Emby " + strings.Join(parts, ", ")
}

func authTokenFromValue(auth string) string {
	matches := mediaBrowserTokenRE.FindStringSubmatch(strings.TrimSpace(auth))
	if len(matches) < 2 {
		return ""
	}
	return unquoteAuthFieldValue(matches[1])
}

func authTokenFromHeaders(headers http.Header) string {
	for _, key := range []string{"X-Emby-Authorization", "X-MediaBrowser-Authorization", "Authorization"} {
		if token := authTokenFromValue(headers.Get(key)); token != "" {
			return token
		}
	}
	return ""
}

func unquoteAuthFieldValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
		value = strings.ReplaceAll(value, `\"`, `"`)
		value = strings.ReplaceAll(value, `\\`, `\`)
	}
	return value
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
