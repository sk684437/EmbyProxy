package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"embyproxy/internal/localtime"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

type Service struct {
	store *storage.Store
	log   *logging.Logger
	http  *http.Client
}

func New(store *storage.Store, log *logging.Logger) *Service {
	return &Service{store: store, log: log, http: &http.Client{Timeout: 12 * time.Second}}
}

func (s *Service) Send(ctx context.Context, token, chat, text string) bool {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(chat) == "" || strings.TrimSpace(text) == "" {
		return false
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id":                  strings.TrimSpace(chat),
		"text":                     text,
		"disable_web_page_preview": true,
	})
	url := "https://api.telegram.org/bot" + strings.TrimSpace(token) + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.http.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 300
}

var digestTimestampsRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(:\d{2})?`)
var digestDateRe = regexp.MustCompile(`· \d{4}-\d{2}-\d{2}`)

const reportHeaderPrefix = "📊 Emby 播放日报 · "

func (s *Service) BuildReport(ctx context.Context, now int64) (string, error) {
	day := storage.BeijingDate(now)
	stats, err := s.store.GetTodayStats(ctx)
	if err != nil {
		return "", err
	}
	today := summarize(stats.Today)
	yesterday := summarize(stats.Yesterday)
	kv := s.store.KV()
	proxyPlaysToday := int64Value(mustKVGet(ctx, kv, "stats:proxyPlays:"+day))
	directPlaysToday := int64Value(mustKVGet(ctx, kv, "stats:directPlays:"+day))
	yesterdayDate := previousReportDate(now)
	proxyPlaysYesterday := int64Value(mustKVGet(ctx, kv, "stats:proxyPlays:"+yesterdayDate))
	directPlaysYesterday := int64Value(mustKVGet(ctx, kv, "stats:directPlays:"+yesterdayDate))
	nodeDisplay := map[string]string{}
	if nodes, err := s.store.ListNodes(ctx, "admin"); err == nil {
		for _, node := range nodes {
			display := strings.TrimSpace(node.DisplayName)
			if display == "" {
				display = node.Name
			}
			nodeDisplay[strings.ToLower(node.Name)] = display
		}
	}
	return buildReportText(day, today, yesterday, proxyPlaysToday, directPlaysToday, proxyPlaysYesterday, directPlaysYesterday, nodeDisplay), nil
}

func (s *Service) CheckAndSendReport(ctx context.Context) error {
	cfg, err := s.store.GetTGConfig(ctx)
	if err != nil || !cfg.Enabled || cfg.Token == "" || cfg.Chat == "" {
		return err
	}
	now := time.Now().UnixMilli()
	day := storage.BeijingDate(now)
	hhmm := storage.BeijingHHMM(now)
	reportTime := cfg.ReportTime
	if reportTime == "" {
		reportTime = "00:00"
	}
	if hhmm < reportTime {
		return nil
	}
	reportMaxPerDay := cfg.ReportMaxPerDay
	if reportMaxPerDay <= 0 {
		reportMaxPerDay = 1
	}
	reportEveryMin := cfg.ReportEveryMin
	if reportEveryMin < 60 {
		reportEveryMin = 1440
	}
	reportChangeOnly := cfg.ReportChangeOnly
	kv := s.store.KV()
	cntKey := "report:cnt:" + day
	lastKey := "report:last:" + day
	digestKey := "report:digest:" + day
	cnt := int64Value(mustKVGet(ctx, kv, cntKey))
	if int(cnt) >= reportMaxPerDay {
		return nil
	}
	lastTS := int64Value(mustKVGet(ctx, kv, lastKey))
	if lastTS > 0 && now-lastTS < int64(reportEveryMin)*60000 {
		return nil
	}
	text, err := s.BuildReport(ctx, now)
	if err != nil {
		return err
	}
	digestText := digestTimestampsRe.ReplaceAllString(text, "")
	digestText = digestDateRe.ReplaceAllString(digestText, "")
	digest := storage.FNV1a(digestText)
	prevDigest := mustKVGet(ctx, kv, digestKey)
	if reportChangeOnly && prevDigest == digest {
		return nil
	}
	if !s.Send(ctx, cfg.Token, cfg.Chat, text) {
		s.log.Warn("telegram", "daily report send failed", map[string]any{"event": "dailyReportSendFailed", "day": day})
		return nil
	}
	_ = kv.Put(ctx, cntKey, strconv.FormatInt(cnt+1, 10))
	_ = kv.Put(ctx, lastKey, strconv.FormatInt(now, 10))
	_ = kv.Put(ctx, digestKey, digest)
	s.log.Info("telegram", "daily report sent", map[string]any{"event": "dailyReportSent", "day": day, "count": cnt + 1})
	return nil
}

func buildReportText(day string, today, yesterday summary, proxyPlaysToday, directPlaysToday, proxyPlaysYesterday, directPlaysYesterday int64, nodeDisplay map[string]string) string {
	if today.Plays == 0 {
		return buildEmptyDayReport(day, yesterday, proxyPlaysYesterday, directPlaysYesterday, nodeDisplay)
	}
	lines := []string{
		reportHeaderPrefix + day,
		"",
		fmt.Sprintf("▶ 播放 %d 次 · %d 会话 · %d 节点", today.Plays, today.Sessions, len(today.NodeMap)),
	}
	total := proxyPlaysToday + directPlaysToday
	lines = append(lines, fmt.Sprintf("   代理 %d | 302直链 %d (%s)", proxyPlaysToday, directPlaysToday, formatPercent(directPlaysToday, total)))
	lines = append(lines, fmt.Sprintf("   入站 %s | 出站 %s", formatBytes(today.InboundBytes), formatBytes(today.OutboundBytes)))
	if today.Errors > 0 {
		lines = append(lines, fmt.Sprintf("   ⚠️ 5xx: %d 次", today.Errors))
	}
	if yesterday.Plays > 0 {
		lines = append(lines, "", fmt.Sprintf("📈 较昨日  播放 %s · 会话 %s · 流量 %s",
			formatSignedInt(today.Plays-yesterday.Plays),
			formatSignedInt(today.Sessions-yesterday.Sessions),
			formatSignedBytes(today.OutboundBytes-yesterday.OutboundBytes)))
	}
	lines = append(lines, "", "🏆 节点排行:")
	lines = append(lines, rankEntries(today.NodeMap, today.Plays, nodeDisplay)...)
	lines = append(lines, "", "📱 客户端排行:")
	lines = append(lines, rankEntries(today.ClientMap, today.Plays, nil)...)
	return strings.Join(lines, "\n")
}

func previousReportDate(now int64) string {
	return localtime.FromUnixMilli(now).AddDate(0, 0, -1).Format("2006-01-02")
}

func buildEmptyDayReport(day string, yesterday summary, proxyPlaysYesterday, directPlaysYesterday int64, nodeDisplay map[string]string) string {
	lines := []string{
		reportHeaderPrefix + day,
		"",
		"📭 今日无播放",
	}
	if yesterday.Plays > 0 {
		lines = append(lines, "", "📅 昨日回顾")
		lines = append(lines, fmt.Sprintf("▶ 播放 %d 次 · %d 会话 · %d 节点", yesterday.Plays, yesterday.Sessions, len(yesterday.NodeMap)))
		total := proxyPlaysYesterday + directPlaysYesterday
		lines = append(lines, fmt.Sprintf("   代理 %d | 302直链 %d (%s)", proxyPlaysYesterday, directPlaysYesterday, formatPercent(directPlaysYesterday, total)))
		lines = append(lines, fmt.Sprintf("   入站 %s | 出站 %s", formatBytes(yesterday.InboundBytes), formatBytes(yesterday.OutboundBytes)))
		if yesterday.Errors > 0 {
			lines = append(lines, fmt.Sprintf("   ⚠️ 5xx: %d 次", yesterday.Errors))
		}
		if len(yesterday.NodeMap) > 0 {
			lines = append(lines, "", "🏆 节点排行:")
			lines = append(lines, rankEntries(yesterday.NodeMap, yesterday.Plays, nodeDisplay)...)
		}
		if len(yesterday.ClientMap) > 0 {
			lines = append(lines, "", "📱 客户端排行:")
			lines = append(lines, rankEntries(yesterday.ClientMap, yesterday.Plays, nil)...)
		}
	}
	return strings.Join(lines, "\n")
}

func (s *Service) CheckKeepaliveAndNotify(ctx context.Context) error {
	cfg, err := s.store.GetTGConfig(ctx)
	if err != nil || !cfg.Enabled || cfg.Token == "" || cfg.Chat == "" {
		return err
	}
	now := time.Now().UnixMilli()
	day := storage.BeijingDate(now)
	hhmm := storage.BeijingHHMM(now)
	nodes, err := s.store.ListNodes(ctx, "admin")
	if err != nil {
		return err
	}
	states, err := s.store.GetAllKeepaliveStates(ctx)
	if err != nil {
		return err
	}
	stateMap := map[string]storage.KeepaliveState{}
	for _, state := range states {
		stateMap[state.Node] = state
	}
	for _, node := range nodes {
		if node.RenewDays <= 0 {
			continue
		}
		state := stateMap["admin:"+node.Name]
		lastPlayTS := state.LastPlayTS
		if lastPlayTS == 0 {
			lastPlayTS = state.AnchorTS
		}
		dueTS := lastPlayTS + int64(node.RenewDays)*86400000
		remindFromTS := dueTS - int64(node.RemindBeforeDays)*86400000
		if now < remindFromTS {
			continue
		}
		keepaliveAt := node.KeepaliveAt
		if keepaliveAt == "" {
			keepaliveAt = "00:00"
		}
		if hhmm < keepaliveAt {
			continue
		}
		maxPerDay := node.KeepaliveMaxPerDay
		if maxPerDay <= 0 {
			maxPerDay = 1
		}
		notifyCount := 0
		if state.NotifyCountDay == day {
			notifyCount = state.NotifyCount
		}
		if notifyCount >= maxPerDay {
			continue
		}
		kv := s.store.KV()
		lastNotifyKey := "keepalive:last:admin:" + node.Name + ":" + day
		lastNotifyTS := int64Value(mustKVGet(ctx, kv, lastNotifyKey))
		if lastNotifyTS > 0 && now-lastNotifyTS < 60*60000 {
			continue
		}
		daysLeft := int((dueTS - now + 86400000 - 1) / 86400000)
		if daysLeft < 0 {
			daysLeft = 0
		}
		lastPlay := "从未"
		if lastPlayTS > 0 {
			lastPlay = localtime.FormatUnixMilli(lastPlayTS, "2006-01-02 15:04")
		}
		display := node.DisplayName
		if display == "" {
			display = node.Name
		}
		lines := []string{
			"保号提醒：" + display,
			"节点：" + node.Name,
			fmt.Sprintf("保号周期：%d 天", node.RenewDays),
			fmt.Sprintf("到期还剩：%d 天", daysLeft),
			"上次播放：" + lastPlay,
		}
		if node.Note != "" {
			lines = append(lines, "备注："+node.Note)
		}
		digestKey := "keepalive:digest:admin:" + node.Name + ":" + day
		digest := storage.FNV1a(strings.Join([]string{node.Name, strconv.Itoa(node.RenewDays), strconv.Itoa(node.RemindBeforeDays), strconv.FormatInt(dueTS, 10), strconv.FormatInt(lastPlayTS, 10)}, "|"))
		prevDigest := mustKVGet(ctx, kv, digestKey)
		if node.KeepaliveChangeOnly && prevDigest == digest {
			continue
		}
		if !s.Send(ctx, cfg.Token, cfg.Chat, strings.Join(lines, "\n")) {
			s.log.Warn("telegram", "keepalive send failed", map[string]any{"event": "keepaliveSendFailed", "node": node.Name, "day": day})
			continue
		}
		_ = kv.Put(ctx, lastNotifyKey, strconv.FormatInt(now, 10))
		_ = kv.Put(ctx, digestKey, digest)
		_ = s.store.UpdateKeepaliveNotify(ctx, "admin", node.Name, day, notifyCount+1, day)
		s.log.Info("telegram", "keepalive sent", map[string]any{"event": "keepaliveSent", "node": node.Name, "day": day, "count": notifyCount + 1})
	}
	return nil
}

type summary struct {
	Plays         int64
	InboundBytes  int64
	OutboundBytes int64
	Sessions      int64
	Errors        int64
	NodeMap       map[string]int64
	ClientMap     map[string]int64
}

func summarize(rows []storage.PlayStat) summary {
	out := summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}}
	for _, row := range rows {
		out.Plays += row.Plays
		out.InboundBytes += row.InboundBytes
		out.OutboundBytes += row.OutboundBytes
		out.Sessions += row.Sessions
		out.Errors += row.Errors
		out.NodeMap[row.Node] += row.Plays
		out.ClientMap[row.Client] += row.Plays
	}
	return out
}

func rankEntries(values map[string]int64, total int64, display map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	type pair struct {
		Key   string
		Value int64
	}
	pairs := make([]pair, 0, len(values))
	for key, value := range values {
		pairs = append(pairs, pair{Key: key, Value: value})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Value > pairs[j].Value })
	if len(pairs) > 99 {
		pairs = pairs[:99]
	}
	lines := make([]string, len(pairs))
	for i, p := range pairs {
		name := p.Key
		if display != nil && display[strings.ToLower(p.Key)] != "" {
			name = display[strings.ToLower(p.Key)]
		}
		lines[i] = fmt.Sprintf("   %d. %s — %d 次 (%s)", i+1, name, p.Value, formatPercent(p.Value, total))
	}
	return lines
}

func formatBytes(value int64) string {
	if value <= 0 {
		return "0B"
	}
	units := []struct {
		name   string
		size   float64
		digits int
	}{
		{name: "PB", size: 1e15, digits: 2},
		{name: "TB", size: 1e12, digits: 2},
		{name: "GB", size: 1e9, digits: 2},
		{name: "MB", size: 1e6, digits: 1},
	}
	for _, unit := range units {
		if float64(value) >= unit.size {
			return fmt.Sprintf("%.*f %s", unit.digits, float64(value)/unit.size, unit.name)
		}
	}
	if value >= 1e3 {
		return fmt.Sprintf("%.1f KB", float64(value)/1e3)
	}
	return fmt.Sprintf("%dB", value)
}

func formatSignedBytes(value int64) string {
	if value == 0 {
		return "0B"
	}
	prefix := "+"
	if value < 0 {
		prefix = "-"
		value = -value
	}
	return prefix + formatBytes(value)
}

func formatSignedInt(value int64) string {
	if value > 0 {
		return "+" + strconv.FormatInt(value, 10)
	}
	return strconv.FormatInt(value, 10)
}

func formatPercent(part, total int64) string {
	if total <= 0 {
		if part > 0 {
			return "100.0%"
		}
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(part)*100/float64(total))
}

func mustKVGet(ctx context.Context, kv *storage.KV, key string) string {
	value, ok, err := kv.Get(ctx, key)
	if err != nil || !ok {
		return ""
	}
	return value
}

func int64Value(value string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return n
}
