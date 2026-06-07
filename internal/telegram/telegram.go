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
	directEstGB := cfg.DirectEstGB
	if directEstGB <= 0 {
		directEstGB = 1.2
	}
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
	stats, err := s.store.GetTodayStats(ctx)
	if err != nil {
		return err
	}
	today := summarize(stats.Today)
	yesterday := summarize(stats.Yesterday)
	proxyPlaysToday := int64Value(mustKVGet(ctx, kv, "stats:proxyPlays:"+day))
	directPlaysToday := int64Value(mustKVGet(ctx, kv, "stats:directPlays:"+day))
	yDay := storage.BeijingDate(time.Now().AddDate(0, 0, -1).UnixMilli())
	proxyPlaysYest := int64Value(mustKVGet(ctx, kv, "stats:proxyPlays:"+yDay))
	directPlaysYest := int64Value(mustKVGet(ctx, kv, "stats:directPlays:"+yDay))
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
	lines := []string{
		"Emby 播放日报 · " + day,
		"",
		fmt.Sprintf("今日: %d 次播放 | %d 节点活跃", today.Plays, len(today.NodeMap)),
		fmt.Sprintf("  代理: %d | 直连: %d", proxyPlaysToday, directPlaysToday),
		fmt.Sprintf("  流量: %s%s", formatBytes(today.Bytes), directEstimate(directPlaysToday, directEstGB)),
	}
	if today.Errors > 0 {
		lines = append(lines, fmt.Sprintf("  %d 次 5xx 错误", today.Errors))
	}
	lines = append(lines,
		"",
		fmt.Sprintf("昨日: %d 次播放 | %d 节点活跃", yesterday.Plays, len(yesterday.NodeMap)),
		fmt.Sprintf("  代理: %d | 直连: %d", proxyPlaysYest, directPlaysYest),
		fmt.Sprintf("  流量: %s%s", formatBytes(yesterday.Bytes), directEstimate(directPlaysYest, directEstGB)),
	)
	for _, line := range rankLines("今日节点排行", today.NodeMap, nodeDisplay) {
		lines = append(lines, line)
	}
	for _, line := range rankLines("今日客户端排行", today.ClientMap, nil) {
		lines = append(lines, line)
	}
	text := strings.Join(lines, "\n")
	digestText := regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(:\d{2})?`).ReplaceAllString(text, "")
	digestText = regexp.MustCompile(`· \d{4}-\d{2}-\d{2}`).ReplaceAllString(digestText, "")
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
			lastPlay = time.UnixMilli(lastPlayTS).UTC().Format("2006-01-02 15:04")
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
	Plays     int64
	Bytes     int64
	Sessions  int64
	Errors    int64
	NodeMap   map[string]int64
	ClientMap map[string]int64
}

func summarize(rows []storage.PlayStat) summary {
	out := summary{NodeMap: map[string]int64{}, ClientMap: map[string]int64{}}
	for _, row := range rows {
		out.Plays += row.Plays
		out.Bytes += row.Bytes
		out.Sessions += row.Sessions
		out.Errors += row.Errors
		out.NodeMap[row.Node] += row.Plays
		out.ClientMap[row.Client] += row.Plays
	}
	return out
}

func rankLines(title string, values map[string]int64, display map[string]string) []string {
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
	lines := []string{"", title + ":"}
	for _, p := range pairs {
		name := p.Key
		if display != nil && display[strings.ToLower(p.Key)] != "" {
			name = display[strings.ToLower(p.Key)]
		}
		lines = append(lines, fmt.Sprintf("  %s: %d 次", name, p.Value))
	}
	return lines
}

func formatBytes(value int64) string {
	if value <= 0 {
		return "0B"
	}
	gb := float64(value) / 1e9
	if gb >= 1 {
		return fmt.Sprintf("%.2f GB", gb)
	}
	return fmt.Sprintf("%.1f MB", float64(value)/1e6)
}

func directEstimate(plays int64, gb float64) string {
	if plays <= 0 {
		return ""
	}
	return fmt.Sprintf(" + 直连估算 %.1f GB", float64(plays)*gb)
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
