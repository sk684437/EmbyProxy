package storage

import (
	"encoding/json"
	"hash/fnv"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"embyproxy/internal/localtime"
)

type Node struct {
	Name                string `json:"name"`
	Target              string `json:"target"`
	StreamTarget        string `json:"streamTarget,omitempty"`
	Fav                 bool   `json:"fav"`
	Rank                *int   `json:"rank,omitempty"`
	Secret              string `json:"secret"`
	Tag                 string `json:"tag"`
	Note                string `json:"note"`
	DisplayName         string `json:"displayName"`
	DirectExternal      bool   `json:"directExternal"`
	RenewDays           int    `json:"renewDays"`
	RemindBeforeDays    int    `json:"remindBeforeDays"`
	KeepaliveAt         string `json:"keepaliveAt"`
	KeepaliveMaxPerDay  int    `json:"keepaliveMaxPerDay"`
	KeepaliveChangeOnly bool   `json:"keepaliveChangeOnly"`
	Impersonate         bool   `json:"impersonate"`
	ImpersonateProfile  string `json:"impersonateProfile"`
	LastPlayAt          int64  `json:"lastPlayAt,omitempty"`
}

type TGConfig struct {
	Enabled          bool   `json:"enabled"`
	Token            string `json:"token"`
	Chat             string `json:"chat"`
	ReportTime       string `json:"reportTime"`
	ReportEveryMin   int    `json:"reportEveryMin"`
	ReportMaxPerDay  int    `json:"reportMaxPerDay"`
	ReportChangeOnly bool   `json:"reportChangeOnly"`
}

type SystemConfig struct {
	LogLevel                    string `json:"logLevel"`
	LogAccess                   bool   `json:"logAccess"`
	CapyStripEmby               string `json:"capyStripEmby"`
	EmosCompat                  bool   `json:"emosCompat"`
	EmosMatchHosts              string `json:"emosMatchHosts"`
	EmosProxyID                 string `json:"emosProxyId"`
	EmosProxyName               string `json:"emosProxyName"`
	CORSAllowOrigin             string `json:"corsAllowOrigin"`
	ExternalAllowHosts          string `json:"externalAllowHosts"`
	ExternalAllowAny            bool   `json:"externalAllowAny"`
	TrustProxy                  bool   `json:"trustProxy"`
	ImageProxyLimitEnabled      bool   `json:"imageProxyLimitEnabled"`
	ImageProxyMaxConcurrent     int    `json:"imageProxyMaxConcurrent"`
	ImageProxyRequestIntervalMS int    `json:"imageProxyRequestIntervalMs"`
	ImageCacheEnabled           bool   `json:"imageCacheEnabled"`
	ImageCacheTTLDays           int    `json:"imageCacheTtlDays"`
	TrafficCaptureEnabled       bool   `json:"trafficCaptureEnabled"`
	TrafficCaptureFile          string `json:"trafficCaptureFile"`
	TrafficCaptureBodyMax       int64  `json:"trafficCaptureBodyMax"`
	TrafficCaptureTextTypes     string `json:"trafficCaptureTextTypes"`
}

const DefaultTrafficCaptureTextTypes = "application/json,application/xml,text/xml," +
	"application/vnd.apple.mpegurl,application/x-mpegurl,application/mpegurl," +
	"audio/mpegurl,audio/x-mpegurl,application/dash+xml"

var targetSplitRE = regexp.MustCompile(`\r?\n|[;,，；|]+`)

func DefaultSystemConfig() SystemConfig {
	return SystemConfig{
		LogLevel:                    "info",
		LogAccess:                   true,
		CapyStripEmby:               "0",
		TrustProxy:                  false,
		ImageProxyLimitEnabled:      false,
		ImageProxyMaxConcurrent:     4,
		ImageProxyRequestIntervalMS: 250,
		ImageCacheEnabled:           false,
		ImageCacheTTLDays:           30,
		TrafficCaptureFile:          "./data/traffic-captures.jsonl",
		TrafficCaptureBodyMax:       262144,
		TrafficCaptureTextTypes:     DefaultTrafficCaptureTextTypes,
	}
}

type PlayStat struct {
	Day      string `json:"day"`
	Node     string `json:"node"`
	Client   string `json:"client"`
	Plays    int64  `json:"plays"`
	Bytes    int64  `json:"bytes"`
	Sessions int64  `json:"sessions"`
	Errors   int64  `json:"errors"`
}

type TodayStats struct {
	Today     []PlayStat `json:"today"`
	Yesterday []PlayStat `json:"yesterday"`
}

type KeepaliveState struct {
	Node           string
	AnchorTS       int64
	LastPlayTS     int64
	LastNotifyDay  string
	NotifyCountDay string
	NotifyCount    int
}

type HostMatch struct {
	Name   string
	Secret string
}

type packedNode struct {
	Target              string `json:"t,omitempty"`
	StreamTarget        string `json:"st,omitempty"`
	Fav                 int    `json:"f,omitempty"`
	Rank                *int   `json:"r,omitempty"`
	Secret              string `json:"s,omitempty"`
	Tag                 string `json:"g,omitempty"`
	Note                string `json:"n,omitempty"`
	DisplayName         string `json:"d,omitempty"`
	DirectExternal      int    `json:"de,omitempty"`
	RenewDays           int    `json:"xd,omitempty"`
	RemindBeforeDays    int    `json:"xb,omitempty"`
	KeepaliveAt         string `json:"xh,omitempty"`
	KeepaliveMaxPerDay  int    `json:"xk,omitempty"`
	KeepaliveChangeOnly *int   `json:"xco,omitempty"`
	Impersonate         *int   `json:"im,omitempty"`
	ImpersonateProfile  string `json:"ip,omitempty"`
}

func PackNode(node Node) (string, error) {
	p := packedNode{
		Target:             node.Target,
		StreamTarget:       node.StreamTarget,
		Rank:               node.Rank,
		Secret:             node.Secret,
		Tag:                node.Tag,
		Note:               node.Note,
		DisplayName:        node.DisplayName,
		RenewDays:          node.RenewDays,
		RemindBeforeDays:   node.RemindBeforeDays,
		KeepaliveAt:        node.KeepaliveAt,
		ImpersonateProfile: "",
	}
	if node.Fav {
		p.Fav = 1
	}
	if node.DirectExternal {
		p.DirectExternal = 1
	}
	if node.KeepaliveMaxPerDay != 0 && node.KeepaliveMaxPerDay != 1 {
		p.KeepaliveMaxPerDay = node.KeepaliveMaxPerDay
	}
	if !node.KeepaliveChangeOnly {
		v := 0
		p.KeepaliveChangeOnly = &v
	}
	if !node.Impersonate {
		v := 0
		p.Impersonate = &v
	}
	if node.ImpersonateProfile != "" && node.ImpersonateProfile != "yamby" {
		p.ImpersonateProfile = node.ImpersonateProfile
	}
	b, err := json.Marshal(p)
	return string(b), err
}

func UnpackNode(name, packed string) (Node, bool) {
	var p packedNode
	if err := json.Unmarshal([]byte(packed), &p); err != nil {
		return Node{}, false
	}
	return Node{
		Name:                name,
		Target:              p.Target,
		StreamTarget:        p.StreamTarget,
		Fav:                 p.Fav != 0,
		Rank:                p.Rank,
		Secret:              p.Secret,
		Tag:                 p.Tag,
		Note:                p.Note,
		DisplayName:         p.DisplayName,
		DirectExternal:      p.DirectExternal != 0,
		RenewDays:           p.RenewDays,
		RemindBeforeDays:    p.RemindBeforeDays,
		KeepaliveAt:         p.KeepaliveAt,
		KeepaliveMaxPerDay:  defaultInt(p.KeepaliveMaxPerDay, 1),
		KeepaliveChangeOnly: p.KeepaliveChangeOnly == nil || *p.KeepaliveChangeOnly != 0,
		Impersonate:         p.Impersonate == nil || *p.Impersonate != 0,
		ImpersonateProfile:  defaultString(p.ImpersonateProfile, "yamby"),
	}, true
}

func SplitTargets(value string) []string {
	raw := strings.NewReplacer("\\r\\n", "\n", "\\n", "\n").Replace(value)
	parts := targetSplitRE.Split(raw, -1)
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, strings.TrimRight(v, "/"))
	}
	return out
}

func SortNodes(nodes []Node) {
	sort.SliceStable(nodes, func(i, j int) bool {
		a, b := nodes[i], nodes[j]
		if a.Fav != b.Fav {
			return a.Fav
		}
		if a.Rank != nil && b.Rank != nil {
			return *a.Rank < *b.Rank
		}
		if a.Rank != nil {
			return true
		}
		if b.Rank != nil {
			return false
		}
		return strings.Compare(a.Name, b.Name) < 0
	})
}

func FNV1a(value string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	return strings.TrimLeft(strings.ToLower(strconvHex(uint64(h.Sum32()))), "0")
}

func BeijingDate(ts int64) string {
	return localtime.Date(ts)
}

func BeijingHHMM(ts int64) string {
	return localtime.HHMM(ts)
}

func QueryValue(u *url.URL, names ...string) string {
	if u == nil {
		return ""
	}
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[strings.ToLower(name)] = true
	}
	for key, values := range u.Query() {
		if wanted[strings.ToLower(key)] && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func defaultInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func strconvHex(n uint64) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n&0xf]
		n >>= 4
	}
	return string(b[i:])
}
