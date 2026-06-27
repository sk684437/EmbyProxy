package telegram

import (
	"context"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReportText(t *testing.T) {
	tests := []struct {
		name                 string
		day                  string
		today                summary
		yesterday            summary
		proxyPlaysToday      int64
		directPlaysToday     int64
		proxyPlaysYesterday  int64
		directPlaysYesterday int64
		nodeDisplay          map[string]string
		wantContains         []string
		wantNotContains      []string
	}{
		{
			name: "normal day",
			day:  "2026-06-08",
			today: summary{
				Plays:         12,
				InboundBytes:  10_000_000_000,
				OutboundBytes: 9_000_000_000,
				Sessions:      8,
				Errors:        1,
				NodeMap:       map[string]int64{"alpha": 8, "beta": 4},
				ClientMap:     map[string]int64{"Infuse/8.0": 6, "Emby Theater": 4, "Unknown": 2},
			},
			yesterday: summary{
				Plays:         7,
				InboundBytes:  5_000_000_000,
				OutboundBytes: 4_000_000_000,
				Sessions:      5,
				NodeMap:       map[string]int64{"alpha": 7},
				ClientMap:     map[string]int64{"Infuse/8.0": 7},
			},
			proxyPlaysToday:      9,
			directPlaysToday:     3,
			proxyPlaysYesterday:  6,
			directPlaysYesterday: 1,
			nodeDisplay:          map[string]string{"alpha": "朋友服"},
			wantContains: []string{
				"📊 Emby 播放日报 · 2026-06-08",
				"▶ 播放 12 次 · 8 会话 · 2 节点",
				"代理 9 | 302直链 3 (25.0%)",
				"入站 10.00 GB | 出站 9.00 GB",
				"⚠️ 5xx: 1 次",
				"📈 较昨日  播放 +5 · 会话 +3 · 流量 +5.00 GB",
				"🏆 节点排行:",
				"1. 朋友服 — 8 次 (66.7%)",
				"2. beta — 4 次 (33.3%)",
				"📱 客户端排行:",
				"1. Infuse/8.0 — 6 次 (50.0%)",
				"2. Emby Theater — 4 次 (33.3%)",
				"3. Unknown — 2 次 (16.7%)",
			},
		},
		{
			name:  "empty day with yesterday",
			day:   "2026-06-10",
			today: summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			yesterday: summary{
				Plays:         22,
				Sessions:      18,
				InboundBytes:  10_000_000_000,
				OutboundBytes: 9_230_000_000,
				Errors:        2,
				NodeMap:       map[string]int64{"alpha": 15, "beta": 7},
				ClientMap:     map[string]int64{"Infuse/8.0": 14, "Emby Theater": 8},
			},
			proxyPlaysYesterday:  18,
			directPlaysYesterday: 4,
			nodeDisplay:          map[string]string{"alpha": "朋友服"},
			wantContains: []string{
				"📊 Emby 播放日报 · 2026-06-10",
				"📭 今日无播放",
				"📅 昨日回顾",
				"▶ 播放 22 次 · 18 会话 · 2 节点",
				"代理 18 | 302直链 4 (18.2%)",
				"入站 10.00 GB | 出站 9.23 GB",
				"⚠️ 5xx: 2 次",
				"🏆 节点排行:",
				"1. 朋友服 — 15 次 (68.2%)",
				"2. beta — 7 次 (31.8%)",
				"📱 客户端排行:",
				"1. Infuse/8.0 — 14 次 (63.6%)",
				"2. Emby Theater — 8 次 (36.4%)",
			},
			wantNotContains: []string{"📈 较昨日"},
		},
		{
			name: "normal day without errors or yesterday",
			day:  "2026-06-08",
			today: summary{
				Plays:     5,
				Sessions:  3,
				NodeMap:   map[string]int64{"a": 5},
				ClientMap: map[string]int64{"b": 5},
			},
			yesterday:       summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			proxyPlaysToday: 5,
			wantNotContains: []string{"5xx", "较昨日"},
		},
		{
			name:            "empty day without yesterday",
			day:             "2026-06-10",
			today:           summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			yesterday:       summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}},
			wantContains:    []string{"📭 今日无播放"},
			wantNotContains: []string{"昨日"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := buildReportText(
				tt.day,
				tt.today,
				tt.yesterday,
				tt.proxyPlaysToday,
				tt.directPlaysToday,
				tt.proxyPlaysYesterday,
				tt.directPlaysYesterday,
				tt.nodeDisplay,
			)
			assertContainsAll(t, text, tt.wantContains)
			assertContainsNone(t, text, tt.wantNotContains)
		})
	}
}

func assertContainsAll(t *testing.T, text string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Fatalf("report text missing %q\n%s", want, text)
		}
	}
}

func assertContainsNone(t *testing.T, text string, values []string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(text, value) {
			t.Fatalf("report text should not contain %q\n%s", value, text)
		}
	}
}

func TestCheckAndSendReportSkipsWhenReportDisabled(t *testing.T) {
	ctx := context.Background()
	store := newTelegramTestStore(t)
	if err := store.SaveTGConfig(ctx, storage.TGConfig{
		Enabled:       true,
		ReportEnabled: false,
		Token:         "token",
		Chat:          "chat",
		ReportTime:    "00:00",
	}); err != nil {
		t.Fatalf("SaveTGConfig() error = %v", err)
	}

	calls := 0
	service := New(store, logging.New("silent", false))
	service.http = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	if err := service.CheckAndSendReport(ctx); err != nil {
		t.Fatalf("CheckAndSendReport() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("telegram calls = %d, want 0", calls)
	}
}

func TestCheckKeepaliveAndNotifyIgnoresReportDisabled(t *testing.T) {
	ctx := context.Background()
	store := newTelegramTestStore(t)
	if err := store.SaveTGConfig(ctx, storage.TGConfig{
		Enabled:       true,
		ReportEnabled: false,
		Token:         "token",
		Chat:          "chat",
	}); err != nil {
		t.Fatalf("SaveTGConfig() error = %v", err)
	}
	if err := store.SaveNode(ctx, "admin", storage.Node{
		Name:             "alpha",
		Target:           "http://example.test",
		DisplayName:      "Alpha",
		RenewDays:        1,
		RemindBeforeDays: 1,
		KeepaliveAt:      "00:00",
	}); err != nil {
		t.Fatalf("SaveNode() error = %v", err)
	}

	calls := 0
	service := New(store, logging.New("silent", false))
	service.http = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	if err := service.CheckKeepaliveAndNotify(ctx); err != nil {
		t.Fatalf("CheckKeepaliveAndNotify() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("telegram calls = %d, want 1", calls)
	}
}

func newTelegramTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.New() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFormatBytesScalesBeyondGB(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value int64
		want  string
	}{
		{name: "zero", value: 0, want: "0B"},
		{name: "negative", value: -1, want: "0B"},
		{name: "bytes", value: 999, want: "999B"},
		{name: "kilobytes", value: 1_500, want: "1.5 KB"},
		{name: "gigabytes", value: 1_500_000_000, want: "1.50 GB"},
		{name: "terabytes", value: 1_500_000_000_000, want: "1.50 TB"},
		{name: "petabytes", value: 1_500_000_000_000_000, want: "1.50 PB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatBytes(tc.value); got != tc.want {
				t.Fatalf("formatBytes() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatSignedBytes(t *testing.T) {
	if got := formatSignedBytes(-1_500_000_000); got != "-1.50 GB" {
		t.Fatalf("formatSignedBytes() = %q", got)
	}
	if got := formatSignedBytes(0); got != "0B" {
		t.Fatalf("formatSignedBytes(0) = %q", got)
	}
}
