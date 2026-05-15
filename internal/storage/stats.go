package storage

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
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
}

func (s *Store) LogPlayback(ctx context.Context, in PlaybackInput) error {
	if !in.IsPlayback {
		return nil
	}
	now := time.Now().UnixMilli()
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

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO keepalive_state (node, anchor_ts, last_play_ts) VALUES (?, ?, ?)
		ON CONFLICT(node) DO UPDATE SET last_play_ts = excluded.last_play_ts
	`, uid+":"+nodeName, now, now); err != nil {
		return err
	}

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

	bytes := responseBytes(in.Status, in.RespHeader)
	if in.Mode != "proxy" || !countable || bytes < 0 {
		bytes = 0
	}
	sessInc := int64(0)
	if countable {
		sessInc = 1
	}
	if countable && (sessionID != "" || deviceID != "") {
		sessKey := strings.Join([]string{day, nodeName, client, ip, deviceID, sessionID}, "|")
		var lastTS int64
		err := s.db.QueryRowContext(ctx, `SELECT last_ts FROM play_sessions WHERE k = ?`, sessKey).Scan(&lastTS)
		if err == nil && now-lastTS < 15*60*1000 {
			sessInc = 0
		}
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO play_sessions (k, day, last_ts) VALUES (?, ?, ?)
			ON CONFLICT(k) DO UPDATE SET last_ts = excluded.last_ts
		`, sessKey, day, now)
		if err != nil {
			return err
		}
	}
	playInc := sessInc
	errInc := int64(0)
	if in.Status >= 500 {
		errInc = 1
	}
	if countable {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO play_stats (day, node, client, plays, bytes, sessions, errors, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(day, node, client) DO UPDATE SET
				plays = plays + excluded.plays,
				bytes = bytes + excluded.bytes,
				sessions = sessions + excluded.sessions,
				errors = errors + excluded.errors,
				updated_at = excluded.updated_at
		`, day, nodeName, client, playInc, bytes, sessInc, errInc, now); err != nil {
			return err
		}
	}
	if playInc > 0 {
		key := "stats:proxyPlays:" + day
		if in.Mode == "direct" {
			key = "stats:directPlays:" + day
		}
		prevRaw, ok, err := s.KV().Get(ctx, key)
		if err != nil {
			return err
		}
		prev := int64(0)
		if ok {
			prev, _ = strconv.ParseInt(strings.TrimSpace(prevRaw), 10, 64)
		}
		if err := s.KV().Put(ctx, key, strconv.FormatInt(prev+playInc, 10)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetPlayStats(ctx context.Context, days int) ([]PlayStat, error) {
	if days <= 0 {
		days = 7
	}
	cutoff := BeijingDate(time.Now().AddDate(0, 0, -days).UnixMilli())
	rows, err := s.db.QueryContext(ctx, `
		SELECT day, node, client, plays, bytes, sessions, errors
		FROM play_stats WHERE day >= ? ORDER BY day DESC, plays DESC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlayStat{}
	for rows.Next() {
		var stat PlayStat
		if err := rows.Scan(&stat.Day, &stat.Node, &stat.Client, &stat.Plays, &stat.Bytes, &stat.Sessions, &stat.Errors); err != nil {
			return nil, err
		}
		out = append(out, stat)
	}
	return out, rows.Err()
}

func (s *Store) GetTodayStats(ctx context.Context) (TodayStats, error) {
	today := BeijingDate(time.Now().UnixMilli())
	yesterday := BeijingDate(time.Now().AddDate(0, 0, -1).UnixMilli())
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
	rows, err := s.db.QueryContext(ctx, `SELECT day, node, client, plays, bytes, sessions, errors FROM play_stats WHERE day = ?`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlayStat{}
	for rows.Next() {
		var stat PlayStat
		if err := rows.Scan(&stat.Day, &stat.Node, &stat.Client, &stat.Plays, &stat.Bytes, &stat.Sessions, &stat.Errors); err != nil {
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
	case regexp.MustCompile(`/sessions/playing/progress/?$`).MatchString(path):
		return "progress"
	case regexp.MustCompile(`/sessions/playing/stopped/?$`).MatchString(path):
		return "stopped"
	case regexp.MustCompile(`/sessions/playing/?$`).MatchString(path):
		return "playing"
	default:
		return ""
	}
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

func responseBytes(status int, headers http.Header) int64 {
	if cr := headers.Get("Content-Range"); cr != "" {
		m := regexp.MustCompile(`(?i)bytes\s+(\d+)-(\d+)`).FindStringSubmatch(cr)
		if len(m) == 3 {
			start, _ := strconv.ParseInt(m[1], 10, 64)
			end, _ := strconv.ParseInt(m[2], 10, 64)
			if end >= start {
				return end - start + 1
			}
		}
	}
	if cl := headers.Get("Content-Length"); cl != "" {
		n, _ := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		return n
	}
	_ = status
	return 0
}

func cutString(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}
