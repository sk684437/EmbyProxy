package telegram

import (
	"strings"
	"testing"
)

func TestBuildReportTextIncludesExpandedDailyStats(t *testing.T) {
	today := summary{
		Plays:         12,
		InboundBytes:  10_000_000_000,
		OutboundBytes: 9_000_000_000,
		Sessions:      8,
		Errors:        1,
		NodeMap: map[string]int64{
			"alpha": 8,
			"beta":  4,
		},
		ClientMap: map[string]int64{
			"Infuse/8.0":   6,
			"Emby Theater": 4,
			"Unknown":      2,
		},
	}
	yesterday := summary{
		Plays:         7,
		InboundBytes:  5_000_000_000,
		OutboundBytes: 4_000_000_000,
		Sessions:      5,
		Errors:        0,
		NodeMap: map[string]int64{
			"alpha": 7,
		},
		ClientMap: map[string]int64{
			"Infuse/8.0": 7,
		},
	}

	text := buildReportText("2026-06-08", today, yesterday, 9, 3, 6, 1, map[string]string{
		"alpha": "朋友服",
	})

	for _, want := range []string{
		"今日: 12 次播放 | 8 会话 | 2 节点活跃",
		"  代理: 9 | 直连: 3 | 直连占比: 25.0%",
		"  代理流量: 入站 10.00 GB | 出站 9.00 GB | 单次出站: 1.00 GB",
		"  5xx: 1 次",
		"较昨日:",
		"  播放: +5 | 会话: +3 | 流量: 入站 +5.00 GB | 出站 +5.00 GB",
		"  活跃节点: +1 | 5xx: +1",
		"昨日: 7 次播放 | 5 会话 | 1 节点活跃",
		"  代理: 6 | 直连: 1 | 直连占比: 14.3%",
		"  朋友服: 8 次，占 66.7%",
		"  beta: 4 次，占 33.3%",
		"  Infuse/8.0: 6 次，占 50.0%",
		"  Emby Theater: 4 次，占 33.3%",
		"  Unknown: 2 次，占 16.7%",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("report text missing %q\n%s", want, text)
		}
	}
}

func TestReportFormatHelpersHandleEmptyValues(t *testing.T) {
	if got := modeSummaryLine(0, 0); got != "  代理: 0 | 直连: 0 | 直连占比: 0.0%" {
		t.Fatalf("modeSummaryLine() = %q", got)
	}
	if got := trafficSummaryLine(0, 0, 0); got != "  代理流量: 入站 0B | 出站 0B | 单次出站: 0B" {
		t.Fatalf("trafficSummaryLine() = %q", got)
	}
	if got := formatSignedBytes(-1_500_000_000); got != "-1.50 GB" {
		t.Fatalf("formatSignedBytes() = %q", got)
	}
}
