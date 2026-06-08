package storage

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"embyproxy/internal/localtime"
)

var (
	sessionProgressRE = regexp.MustCompile(`/sessions/playing/progress/?$`)
	sessionStoppedRE  = regexp.MustCompile(`/sessions/playing/stopped/?$`)
	sessionPlayingRE  = regexp.MustCompile(`/sessions/playing/?$`)
	playbackMediaRE   = regexp.MustCompile(`(?i)/(videos|audio|items)/([^/?#]+)(?:/|$)`)
)

type PlaybackInput struct {
	Node       Node
	RequestIP  string
	Headers    http.Header
	Status     int
	RespHeader http.Header
	IsPlayback bool
	Mode       string
	RequestURL string
	Method     string
	OccurredAt int64

	TrafficOnly   bool
	InboundBytes  int64
	OutboundBytes int64
}

const (
	playbackAsyncQueueSize    = 4096
	playbackAsyncWriteTimeout = 5 * time.Second
)

func (s *Store) startPlaybackAsyncLogger() {
	if s == nil {
		return
	}
	s.playbackQueue = make(chan PlaybackInput, playbackAsyncQueueSize)
	s.playbackWG.Add(1)
	go s.runPlaybackAsyncLogger()
}

func (s *Store) closePlaybackAsyncLogger() {
	if s == nil {
		return
	}
	s.playbackMu.Lock()
	if !s.playbackClosed {
		s.playbackClosed = true
		if s.playbackQueue != nil {
			close(s.playbackQueue)
		}
	}
	s.playbackMu.Unlock()
	s.playbackWG.Wait()
}

func (s *Store) runPlaybackAsyncLogger() {
	defer s.playbackWG.Done()
	for in := range s.playbackQueue {
		ctx, cancel := context.WithTimeout(context.Background(), playbackAsyncWriteTimeout)
		if in.TrafficOnly {
			_ = s.LogPlaybackTraffic(ctx, in)
		} else {
			_ = s.LogPlayback(ctx, in)
		}
		cancel()
	}
}

func (s *Store) LogPlaybackAsync(in PlaybackInput) bool {
	if s == nil || (!in.IsPlayback && !in.TrafficOnly) {
		return true
	}
	in = clonePlaybackInput(in)
	s.playbackMu.RLock()
	defer s.playbackMu.RUnlock()
	if s.playbackClosed || s.playbackQueue == nil {
		return false
	}
	select {
	case s.playbackQueue <- in:
		return true
	default:
		atomic.AddUint64(&s.playbackDropped, 1)
		return false
	}
}

func clonePlaybackInput(in PlaybackInput) PlaybackInput {
	in.Headers = cloneHTTPHeader(in.Headers)
	in.RespHeader = cloneHTTPHeader(in.RespHeader)
	return in
}

func cloneHTTPHeader(in http.Header) http.Header {
	out := http.Header{}
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func (s *Store) LogPlayback(ctx context.Context, in PlaybackInput) error {
	if !in.IsPlayback {
		return nil
	}
	now := playbackOccurredAt(in)
	day := BeijingDate(now)
	uid := "admin"
	nodeName := strings.ToLower(strings.TrimSpace(in.Node.Name))
	if nodeName == "" {
		nodeName = "unknown"
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = strings.ToUpper(strings.TrimSpace(in.Headers.Get("method")))
	}
	if method == "" {
		method = "GET"
	}
	sessionEvent := sessionPlayingEvent(in.RequestURL)
	countable := (method == http.MethodGet || method == http.MethodHead) && sessionEvent == ""

	ua := cutString(in.Headers.Get("User-Agent"), 128)
	client := ua
	if client == "" {
		client = "Unknown"
	}
	ip := strings.TrimSpace(strings.Split(in.RequestIP, ",")[0])
	if ip == "" {
		ip = "unknown"
	}
	reqURL := parseRequestURL(in.RequestURL)
	deviceID := cutString(headerOrQuery(in.Headers, reqURL, "X-Emby-Device-Id", "X-MediaBrowser-Device-Id", "DeviceId", "deviceId"), 64)
	sessionID := cutString(headerOrQuery(in.Headers, reqURL, "X-Emby-Session-Id", "SessionId", "PlaySessionId", "playSessionId"), 64)

	sessInc := int64(0)
	if countable {
		sessInc = 1
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO keepalive_state (node, anchor_ts, last_play_ts) VALUES (?, ?, ?)
		ON CONFLICT(node) DO UPDATE SET last_play_ts = MAX(COALESCE(keepalive_state.last_play_ts, 0), excluded.last_play_ts)
	`, uid+":"+nodeName, now, now); err != nil {
		return err
	}

	if countable && (sessionID != "" || deviceID != "") {
		sessKey := strings.Join([]string{day, nodeName, client, ip, deviceID, sessionID}, "|")
		var lastTS int64
		err := tx.QueryRowContext(ctx, `SELECT last_ts FROM play_sessions WHERE k = ?`, sessKey).Scan(&lastTS)
		if err == nil && now-lastTS < 15*60*1000 {
			sessInc = 0
		} else if err != nil && err != sql.ErrNoRows {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO play_sessions (k, day, last_ts) VALUES (?, ?, ?)
			ON CONFLICT(k) DO UPDATE SET last_ts = MAX(play_sessions.last_ts, excluded.last_ts)
		`, sessKey, day, now)
		if err != nil {
			return err
		}
	}
	playInc := sessInc
	if countable {
		if mediaKey := playbackMediaKey(reqURL); mediaKey != "" {
			playInc = 1
			playKey := strings.Join([]string{day, nodeName, client, ip, deviceID, sessionID, mediaKey}, "|")
			var lastTS int64
			err := tx.QueryRowContext(ctx, `SELECT last_ts FROM play_events WHERE k = ?`, playKey).Scan(&lastTS)
			if err == nil && now-lastTS < 15*60*1000 {
				playInc = 0
			} else if err != nil && err != sql.ErrNoRows {
				return err
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO play_events (k, day, last_ts) VALUES (?, ?, ?)
				ON CONFLICT(k) DO UPDATE SET last_ts = MAX(play_events.last_ts, excluded.last_ts)
			`, playKey, day, now)
			if err != nil {
				return err
			}
		}
	}
	errInc := int64(0)
	if in.Status >= 500 {
		errInc = 1
	}
	if countable {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO play_stats (day, node, client, plays, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at)
			VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?, ?)
			ON CONFLICT(day, node, client) DO UPDATE SET
				plays = plays + excluded.plays,
				sessions = sessions + excluded.sessions,
				errors = errors + excluded.errors,
				updated_at = MAX(play_stats.updated_at, excluded.updated_at)
		`, day, nodeName, client, playInc, sessInc, errInc, now); err != nil {
			return err
		}
	}
	if playInc > 0 {
		key := "stats:proxyPlays:" + day
		if in.Mode == "direct" {
			key = "stats:directPlays:" + day
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO proxy_kv (k, v, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(k) DO UPDATE SET
				v = CAST(CAST(proxy_kv.v AS INTEGER) + CAST(excluded.v AS INTEGER) AS TEXT),
				updated_at = MAX(proxy_kv.updated_at, excluded.updated_at)
		`, key, strconv.FormatInt(playInc, 10), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) LogPlaybackTraffic(ctx context.Context, in PlaybackInput) error {
	if !in.IsPlayback {
		return nil
	}
	now := playbackOccurredAt(in)
	day := BeijingDate(now)
	nodeName := strings.ToLower(strings.TrimSpace(in.Node.Name))
	if nodeName == "" {
		nodeName = "unknown"
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = strings.ToUpper(strings.TrimSpace(in.Headers.Get("method")))
	}
	if method == "" {
		method = "GET"
	}
	countable := method == http.MethodGet && sessionPlayingEvent(in.RequestURL) == ""
	if in.Mode != "proxy" || !countable {
		return nil
	}
	inboundBytes := in.InboundBytes
	if inboundBytes < 0 {
		inboundBytes = 0
	}
	outboundBytes := in.OutboundBytes
	if outboundBytes < 0 {
		outboundBytes = 0
	}
	if inboundBytes == 0 && outboundBytes == 0 {
		return nil
	}
	client := cutString(in.Headers.Get("User-Agent"), 128)
	if client == "" {
		client = "Unknown"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO play_stats (day, node, client, plays, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at)
		VALUES (?, ?, ?, 0, ?, ?, ?, 0, 0, ?)
		ON CONFLICT(day, node, client) DO UPDATE SET
			bytes = bytes + excluded.bytes,
			inbound_bytes = inbound_bytes + excluded.inbound_bytes,
			outbound_bytes = outbound_bytes + excluded.outbound_bytes,
			updated_at = MAX(play_stats.updated_at, excluded.updated_at)
	`, day, nodeName, client, outboundBytes, inboundBytes, outboundBytes, now)
	return err
}

func playbackOccurredAt(in PlaybackInput) int64 {
	if in.OccurredAt > 0 {
		return in.OccurredAt
	}
	return time.Now().UnixMilli()
}

func (s *Store) GetPlayStats(ctx context.Context, days int) ([]PlayStat, error) {
	if days <= 0 {
		days = 7
	}
	cutoff := localtime.Now().AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	rows, err := s.db.QueryContext(ctx, `
		SELECT day, node, client, plays, bytes, inbound_bytes, outbound_bytes, sessions, errors
		FROM play_stats WHERE day >= ? ORDER BY day DESC, plays DESC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlayStat{}
	for rows.Next() {
		var stat PlayStat
		if err := rows.Scan(&stat.Day, &stat.Node, &stat.Client, &stat.Plays, &stat.Bytes, &stat.InboundBytes, &stat.OutboundBytes, &stat.Sessions, &stat.Errors); err != nil {
			return nil, err
		}
		out = append(out, stat)
	}
	return out, rows.Err()
}

func (s *Store) GetTodayStats(ctx context.Context) (TodayStats, error) {
	now := localtime.Now()
	today := now.Format("2006-01-02")
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")
	todayRows, err := s.getStatsForDay(ctx, today)
	if err != nil {
		return TodayStats{}, err
	}
	yesterdayRows, err := s.getStatsForDay(ctx, yesterday)
	if err != nil {
		return TodayStats{}, err
	}
	return TodayStats{Today: todayRows, Yesterday: yesterdayRows}, nil
}

func (s *Store) getStatsForDay(ctx context.Context, day string) ([]PlayStat, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT day, node, client, plays, bytes, inbound_bytes, outbound_bytes, sessions, errors FROM play_stats WHERE day = ?`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlayStat{}
	for rows.Next() {
		var stat PlayStat
		if err := rows.Scan(&stat.Day, &stat.Node, &stat.Client, &stat.Plays, &stat.Bytes, &stat.InboundBytes, &stat.OutboundBytes, &stat.Sessions, &stat.Errors); err != nil {
			return nil, err
		}
		out = append(out, stat)
	}
	return out, rows.Err()
}

func (s *Store) GetAllKeepaliveStates(ctx context.Context) ([]KeepaliveState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node, anchor_ts, last_play_ts, last_notify_day, notify_count_day, notify_count FROM keepalive_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KeepaliveState{}
	for rows.Next() {
		var st KeepaliveState
		var lastNotify, notifyDay sqlNullString
		if err := rows.Scan(&st.Node, &st.AnchorTS, &st.LastPlayTS, &lastNotify, &notifyDay, &st.NotifyCount); err != nil {
			return nil, err
		}
		st.LastNotifyDay = lastNotify.String
		st.NotifyCountDay = notifyDay.String
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) UpdateKeepaliveNotify(ctx context.Context, uid, nodeName, day string, count int, lastNotifyDay string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE keepalive_state SET notify_count_day = ?, notify_count = ?, last_notify_day = ?
		WHERE node = ?
	`, day, count, lastNotifyDay, uid+":"+nodeName)
	return err
}

type sqlNullString struct {
	String string
	Valid  bool
}

func (s *sqlNullString) Scan(value any) error {
	if value == nil {
		s.String = ""
		s.Valid = false
		return nil
	}
	s.Valid = true
	s.String = stringFromAny(value)
	return nil
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func sessionPlayingEvent(raw string) string {
	path := strings.ToLower(parseRequestPath(raw))
	switch {
	case sessionProgressRE.MatchString(path):
		return "progress"
	case sessionStoppedRE.MatchString(path):
		return "stopped"
	case sessionPlayingRE.MatchString(path):
		return "playing"
	default:
		return ""
	}
}

func playbackMediaKey(reqURL *url.URL) string {
	if reqURL == nil {
		return ""
	}
	if id := QueryValue(reqURL, "ItemId", "itemId", "item_id"); id != "" {
		return "item:" + cutString(id, 128)
	}
	if id := QueryValue(reqURL, "MediaId", "mediaId", "media_id"); id != "" {
		return "media:" + cutString(id, 128)
	}
	if m := playbackMediaRE.FindStringSubmatch(reqURL.Path); len(m) == 3 {
		return strings.ToLower(m[1]) + ":" + cutString(m[2], 128)
	}
	if id := QueryValue(reqURL, "MediaSourceId", "mediaSourceId", "media_source_id"); id != "" {
		return "source:" + cutString(id, 128)
	}
	return ""
}

func parseRequestPath(raw string) string {
	u := parseRequestURL(raw)
	if u != nil && u.Path != "" {
		return u.Path
	}
	if idx := strings.IndexByte(raw, '?'); idx >= 0 {
		return raw[:idx]
	}
	if raw == "" {
		return "/"
	}
	return raw
}

func parseRequestURL(raw string) *url.URL {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err == nil {
		if u.Scheme == "" && strings.HasPrefix(raw, "/") {
			u, err = url.Parse("http://local" + raw)
		}
	}
	if err != nil {
		return nil
	}
	return u
}

func headerOrQuery(headers http.Header, u *url.URL, names ...string) string {
	for _, name := range names {
		if value := headers.Get(name); value != "" {
			return value
		}
	}
	return QueryValue(u, names...)
}

func cutString(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}
