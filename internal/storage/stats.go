package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
	Node        Node
	RequestIP   string
	Headers     http.Header
	Status      int
	RespHeader  http.Header
	IsPlayback  bool
	Mode        string
	RequestURL  string
	Method      string
	RequestBody []byte
	OccurredAt  int64

	TrafficOnly   bool
	InboundBytes  int64
	OutboundBytes int64

	PlaybackStateOnly bool
}

const (
	playbackAsyncQueueSize    = 4096
	playbackAsyncWriteTimeout = 5 * time.Second
	playbackBucketMillis      = int64(time.Minute / time.Millisecond)
	// Longer gaps are discarded instead of capped so suspended clients never add inferred playback time.
	playbackMaxIntervalMillis = int64(40 * time.Second / time.Millisecond)
)

type playbackState struct {
	Node              string
	Client            string
	Mode              string
	ItemKey           string
	LastEventTS       int64
	LastPositionTicks int64
	HasPosition       bool
	IsPaused          bool
	Closed            bool
}

type playbackStateUpdate struct {
	Key           string
	Event         string
	Node          string
	Client        string
	Mode          string
	ItemKey       string
	OccurredAt    int64
	PositionTicks int64
	HasPosition   bool
	IsPaused      bool
	HasPaused     bool
}

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

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
	in.RequestBody = append([]byte(nil), in.RequestBody...)
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
	isPlaybackStart := method == http.MethodPost && sessionEvent == "playing"
	countable := isPlaybackStart && playbackStatusSuccessful(in.Status)

	ua := cutString(in.Headers.Get("User-Agent"), 128)
	client := ua
	if client == "" {
		client = "Unknown"
	}
	mode := strings.TrimSpace(in.Mode)
	if mode == "" {
		mode = "proxy"
	}
	ip := strings.TrimSpace(strings.Split(in.RequestIP, ",")[0])
	if ip == "" {
		ip = "unknown"
	}
	reqURL := parseRequestURL(in.RequestURL)
	bodyValues := parsePlaybackRequestBody(in.RequestBody)
	userID := cutString(headerOrQueryOrBody(in.Headers, reqURL, bodyValues, "X-Emby-User-Id", "X-MediaBrowser-User-Id", "UserId", "userId", "user_id"), 64)
	deviceID := cutString(headerOrQueryOrBody(in.Headers, reqURL, bodyValues, "X-Emby-Device-Id", "X-MediaBrowser-Device-Id", "DeviceId", "deviceId", "device_id"), 64)
	sessionID := cutString(headerOrQueryOrBody(in.Headers, reqURL, bodyValues, "X-Emby-Session-Id", "SessionId", "sessionId", "session_id"), 64)
	playSessionID := cutString(headerOrQueryOrBody(in.Headers, reqURL, bodyValues, "PlaySessionId", "playSessionId", "play_session_id"), 128)
	mediaKey := playbackStartMediaKey(reqURL, bodyValues)
	positionTicks, hasPosition := bodyInt64(bodyValues, "PositionTicks", "positionTicks", "position_ticks")
	isPaused, hasPaused := bodyBool(bodyValues, "IsPaused", "isPaused", "is_paused")
	stateKey := playbackStateKey(nodeName, client, ip, userID, deviceID, sessionID, playSessionID, mediaKey)
	playbackAction := method == http.MethodPost && sessionEvent != "" && playbackStatusSuccessful(in.Status)

	sessInc := int64(0)
	if countable {
		sessInc = 1
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if in.PlaybackStateOnly {
		if playbackAction && stateKey != "" {
			if err := updatePlaybackState(ctx, tx, playbackStateUpdate{
				Key:           stateKey,
				Event:         sessionEvent,
				Node:          nodeName,
				Client:        client,
				Mode:          mode,
				ItemKey:       mediaKey,
				OccurredAt:    now,
				PositionTicks: positionTicks,
				HasPosition:   hasPosition,
				IsPaused:      isPaused,
				HasPaused:     hasPaused,
			}); err != nil {
				return err
			}
		}
		return tx.Commit()
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO keepalive_state (node, anchor_ts, last_play_ts) VALUES (?, ?, ?)
		ON CONFLICT(node) DO UPDATE SET last_play_ts = MAX(COALESCE(keepalive_state.last_play_ts, 0), excluded.last_play_ts)
	`, uid+":"+nodeName, now, now); err != nil {
		return err
	}

	sessionActivity := method == http.MethodPost && playbackStatusSuccessful(in.Status) && (sessionEvent == "progress" || sessionEvent == "stopped")
	if countable || sessionActivity {
		sessKey := playbackSessionKey(nodeName, client, ip, userID, deviceID)
		var lastTS int64
		if countable {
			err := tx.QueryRowContext(ctx, `SELECT last_ts FROM play_sessions WHERE k = ?`, sessKey).Scan(&lastTS)
			if err == nil && now-lastTS < 15*60*1000 {
				sessInc = 0
			} else if err != nil && err != sql.ErrNoRows {
				return err
			}
			_, err = tx.ExecContext(ctx, `
				INSERT INTO play_sessions (k, day, last_ts) VALUES (?, ?, ?)
				ON CONFLICT(k) DO UPDATE SET
					day = CASE WHEN excluded.last_ts >= play_sessions.last_ts THEN excluded.day ELSE play_sessions.day END,
					last_ts = MAX(play_sessions.last_ts, excluded.last_ts)
			`, sessKey, day, now)
			if err != nil {
				return err
			}
		} else {
			_, err := tx.ExecContext(ctx, `
				UPDATE play_sessions SET
					day = CASE WHEN ? >= last_ts THEN ? ELSE day END,
					last_ts = MAX(last_ts, ?)
				WHERE k = ?
			`, now, day, now, sessKey)
			if err != nil {
				return err
			}
		}
	}
	if playbackAction && stateKey != "" {
		if err := updatePlaybackState(ctx, tx, playbackStateUpdate{
			Key:           stateKey,
			Event:         sessionEvent,
			Node:          nodeName,
			Client:        client,
			Mode:          mode,
			ItemKey:       mediaKey,
			OccurredAt:    now,
			PositionTicks: positionTicks,
			HasPosition:   hasPosition,
			IsPaused:      isPaused,
			HasPaused:     hasPaused,
		}); err != nil {
			return err
		}
	}
	playInc := int64(0)
	if countable {
		playInc = 1
		playKey := strings.Join([]string{day, nodeName, client, ip, userID, deviceID, sessionID, playSessionID, mediaKey}, "|")
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
	errInc := int64(0)
	if isPlaybackStart && in.Status >= 500 {
		errInc = 1
	}
	if isPlaybackStart && (playInc > 0 || sessInc > 0 || errInc > 0) {
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
		if err := upsertPlayBucket(ctx, tx, now, nodeName, client, mode, playInc, 0, 0, 0, 0, sessInc, errInc); err != nil {
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
	countable := playbackTrafficCountable(method, in.RequestURL)
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
	totalBytes := inboundBytes + outboundBytes
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
	`, day, nodeName, client, totalBytes, inboundBytes, outboundBytes, now)
	if err != nil {
		return err
	}
	return upsertPlayBucket(ctx, s.db, now, nodeName, client, "proxy", 0, 0, totalBytes, inboundBytes, outboundBytes, 0, 0)
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
		SELECT day, node, client, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at
		FROM play_stats WHERE day >= ? ORDER BY day DESC, plays DESC
	`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlayStat{}
	for rows.Next() {
		var stat PlayStat
		if err := rows.Scan(&stat.Day, &stat.Node, &stat.Client, &stat.Plays, &stat.PlaybackMillis, &stat.Bytes, &stat.InboundBytes, &stat.OutboundBytes, &stat.Sessions, &stat.Errors, &stat.LastActivityAt); err != nil {
			return nil, err
		}
		stat.Bytes = stat.InboundBytes + stat.OutboundBytes
		stat.LastActivity = localtime.FormatUnixMilli(stat.LastActivityAt, "2006-01-02 15:04:05")
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
	rows, err := s.db.QueryContext(ctx, `SELECT day, node, client, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors FROM play_stats WHERE day = ?`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlayStat{}
	for rows.Next() {
		var stat PlayStat
		if err := rows.Scan(&stat.Day, &stat.Node, &stat.Client, &stat.Plays, &stat.PlaybackMillis, &stat.Bytes, &stat.InboundBytes, &stat.OutboundBytes, &stat.Sessions, &stat.Errors); err != nil {
			return nil, err
		}
		stat.Bytes = stat.InboundBytes + stat.OutboundBytes
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

func playbackStatusSuccessful(status int) bool {
	return status == 0 || (status >= 200 && status < 300)
}

func playbackTrafficCountable(method, raw string) bool {
	if method != http.MethodGet || sessionPlayingEvent(raw) != "" {
		return false
	}
	path := strings.ToLower(parseRequestPath(raw))
	if strings.Contains(path, "/playbackinfo") || strings.Contains(path, "/additionalparts") {
		return false
	}
	return true
}

func playbackStartMediaKey(reqURL *url.URL, body map[string]any) string {
	if id := bodyOrQuery(body, reqURL, "ItemId", "itemId", "item_id"); id != "" {
		return "item:" + cutString(id, 128)
	}
	if id := bodyOrQuery(body, reqURL, "MediaId", "mediaId", "media_id"); id != "" {
		return "media:" + cutString(id, 128)
	}
	if id := bodyOrQuery(body, reqURL, "MediaSourceId", "mediaSourceId", "media_source_id"); id != "" {
		return "source:" + cutString(id, 128)
	}
	return playbackMediaKey(reqURL)
}

func playbackSessionKey(nodeName, client, ip, userID, deviceID string) string {
	return strings.Join([]string{nodeName, client, ip, userID, deviceID}, "|")
}

func playbackStateKey(nodeName, client, ip, userID, deviceID, sessionID, playSessionID, mediaKey string) string {
	if playSessionID != "" {
		return strings.Join([]string{nodeName, "play", playSessionID}, "|")
	}
	if sessionID != "" {
		return strings.Join([]string{nodeName, "session", sessionID, deviceID, mediaKey}, "|")
	}
	if deviceID != "" && mediaKey != "" {
		return strings.Join([]string{nodeName, "device", deviceID, userID, mediaKey}, "|")
	}
	if mediaKey != "" {
		return strings.Join([]string{nodeName, "fallback", client, ip, userID, mediaKey}, "|")
	}
	return ""
}

func updatePlaybackState(ctx context.Context, tx *sql.Tx, in playbackStateUpdate) error {
	var state playbackState
	var hasPosition, isPaused, closed int
	err := tx.QueryRowContext(ctx, `
		SELECT node, client, mode, item_key, last_event_ts, last_position_ticks, has_position, is_paused, closed
		FROM playback_states WHERE k = ?
	`, in.Key).Scan(
		&state.Node,
		&state.Client,
		&state.Mode,
		&state.ItemKey,
		&state.LastEventTS,
		&state.LastPositionTicks,
		&hasPosition,
		&isPaused,
		&closed,
	)
	if err == sql.ErrNoRows {
		if in.Event == "stopped" {
			return upsertPlaybackState(ctx, tx, playbackState{
				Node:              in.Node,
				Client:            in.Client,
				Mode:              in.Mode,
				ItemKey:           in.ItemKey,
				LastEventTS:       in.OccurredAt,
				LastPositionTicks: in.PositionTicks,
				HasPosition:       in.HasPosition,
				IsPaused:          in.HasPaused && in.IsPaused,
				Closed:            true,
			}, in.Key)
		}
		paused := false
		if in.HasPaused {
			paused = in.IsPaused
		}
		return upsertPlaybackState(ctx, tx, playbackState{
			Node:              in.Node,
			Client:            in.Client,
			Mode:              in.Mode,
			ItemKey:           in.ItemKey,
			LastEventTS:       in.OccurredAt,
			LastPositionTicks: in.PositionTicks,
			HasPosition:       in.HasPosition,
			IsPaused:          paused,
		}, in.Key)
	}
	if err != nil {
		return err
	}
	state.HasPosition = hasPosition != 0
	state.IsPaused = isPaused != 0
	state.Closed = closed != 0
	if in.Event == "playing" {
		if in.OccurredAt <= state.LastEventTS {
			return nil
		}
		paused := false
		if in.HasPaused {
			paused = in.IsPaused
		}
		return upsertPlaybackState(ctx, tx, playbackState{
			Node:              in.Node,
			Client:            in.Client,
			Mode:              in.Mode,
			ItemKey:           in.ItemKey,
			LastEventTS:       in.OccurredAt,
			LastPositionTicks: in.PositionTicks,
			HasPosition:       in.HasPosition,
			IsPaused:          paused,
		}, in.Key)
	}
	if state.Closed || in.OccurredAt < state.LastEventTS {
		return nil
	}
	if in.OccurredAt == state.LastEventTS {
		if in.Event != "stopped" {
			return nil
		}
		state.Closed = true
		return upsertPlaybackState(ctx, tx, state, in.Key)
	}
	if state.ItemKey != "" && in.ItemKey != "" && state.ItemKey != in.ItemKey {
		if in.Event == "stopped" {
			state.LastEventTS = in.OccurredAt
			state.Closed = true
			return upsertPlaybackState(ctx, tx, state, in.Key)
		}
		paused := state.IsPaused
		if in.HasPaused {
			paused = in.IsPaused
		}
		return upsertPlaybackState(ctx, tx, playbackState{
			Node:              in.Node,
			Client:            in.Client,
			Mode:              in.Mode,
			ItemKey:           in.ItemKey,
			LastEventTS:       in.OccurredAt,
			LastPositionTicks: in.PositionTicks,
			HasPosition:       in.HasPosition,
			IsPaused:          paused,
		}, in.Key)
	}

	intervalMillis := in.OccurredAt - state.LastEventTS
	positionChanged := state.HasPosition && in.HasPosition && state.LastPositionTicks != in.PositionTicks
	if intervalMillis <= playbackMaxIntervalMillis && !state.IsPaused && positionChanged {
		if err := addPlaybackDuration(ctx, tx, state.LastEventTS, in.OccurredAt, state.Node, state.Client, state.Mode); err != nil {
			return err
		}
	}
	if in.Event == "stopped" {
		state.LastEventTS = in.OccurredAt
		if in.ItemKey != "" {
			state.ItemKey = in.ItemKey
		}
		if in.HasPosition {
			state.LastPositionTicks = in.PositionTicks
			state.HasPosition = true
		}
		if in.HasPaused {
			state.IsPaused = in.IsPaused
		}
		state.Closed = true
		return upsertPlaybackState(ctx, tx, state, in.Key)
	}

	if in.ItemKey != "" {
		state.ItemKey = in.ItemKey
	}
	state.LastEventTS = in.OccurredAt
	if in.HasPosition {
		state.LastPositionTicks = in.PositionTicks
		state.HasPosition = true
	}
	if in.HasPaused {
		state.IsPaused = in.IsPaused
	}
	return upsertPlaybackState(ctx, tx, state, in.Key)
}

func upsertPlaybackState(ctx context.Context, tx *sql.Tx, state playbackState, key string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO playback_states (
			k, node, client, mode, item_key, last_event_ts, last_position_ticks, has_position, is_paused, closed, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(k) DO UPDATE SET
			node = excluded.node,
			client = excluded.client,
			mode = excluded.mode,
			item_key = excluded.item_key,
			last_event_ts = excluded.last_event_ts,
			last_position_ticks = excluded.last_position_ticks,
			has_position = excluded.has_position,
			is_paused = excluded.is_paused,
			closed = excluded.closed,
			updated_at = excluded.updated_at
	`, key, state.Node, state.Client, state.Mode, state.ItemKey, state.LastEventTS, state.LastPositionTicks, boolInt(state.HasPosition), boolInt(state.IsPaused), boolInt(state.Closed), state.LastEventTS)
	return err
}

func addPlaybackDuration(ctx context.Context, tx *sql.Tx, startTime, endTime int64, node, client, mode string) error {
	type dayDuration struct {
		playbackMillis int64
		activityAt     int64
	}
	daily := make(map[string]dayDuration, 2)
	dayOrder := make([]string, 0, 2)
	for cursor := startTime; cursor < endTime; {
		next := playbackBucketStart(cursor) + playbackBucketMillis
		if next > endTime {
			next = endTime
		}
		playbackMillis := next - cursor
		day := BeijingDate(cursor)
		activityAt := next
		if BeijingDate(activityAt) != day {
			activityAt--
		}
		total, exists := daily[day]
		if !exists {
			dayOrder = append(dayOrder, day)
		}
		total.playbackMillis += playbackMillis
		if activityAt > total.activityAt {
			total.activityAt = activityAt
		}
		daily[day] = total
		if err := upsertPlayBucket(ctx, tx, cursor, node, client, mode, 0, playbackMillis, 0, 0, 0, 0, 0); err != nil {
			return err
		}
		cursor = next
	}
	for _, day := range dayOrder {
		total := daily[day]
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO play_stats (
				day, node, client, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at
			) VALUES (?, ?, ?, 0, ?, 0, 0, 0, 0, 0, ?)
			ON CONFLICT(day, node, client) DO UPDATE SET
				playback_ms = playback_ms + excluded.playback_ms,
				updated_at = MAX(play_stats.updated_at, excluded.updated_at)
		`, day, node, client, total.playbackMillis, total.activityAt); err != nil {
			return err
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
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

func parsePlaybackRequestBody(body []byte) map[string]any {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil
	}
	var out map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil
	}
	return out
}

func headerOrQueryOrBody(headers http.Header, u *url.URL, body map[string]any, names ...string) string {
	if value := headerOrQuery(headers, u, names...); value != "" {
		return value
	}
	return bodyValue(body, names...)
}

func bodyOrQuery(body map[string]any, u *url.URL, names ...string) string {
	if value := bodyValue(body, names...); value != "" {
		return value
	}
	return QueryValue(u, names...)
}

func bodyValue(body map[string]any, names ...string) string {
	if len(body) == 0 {
		return ""
	}
	for _, name := range names {
		if value, ok := body[name]; ok {
			return jsonScalarString(value)
		}
	}
	for key, value := range body {
		for _, name := range names {
			if strings.EqualFold(key, name) {
				return jsonScalarString(value)
			}
		}
	}
	return ""
}

func bodyInt64(body map[string]any, names ...string) (int64, bool) {
	value := bodyValue(body, names...)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func bodyBool(body map[string]any, names ...string) (bool, bool) {
	value := bodyValue(body, names...)
	if value == "" {
		return false, false
	}
	switch value {
	case "1":
		return true, true
	case "0":
		return false, true
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, false
	}
	return parsed, true
}

func jsonScalarString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return strings.TrimSpace(v.String())
	case float64:
		return strings.TrimSpace(strconv.FormatFloat(v, 'f', -1, 64))
	case bool:
		return strconv.FormatBool(v)
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

func cutString(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

func (s *Store) GetRangeStats(ctx context.Context, startTime, endTime int64) ([]PlayStat, int64, int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT node, client, SUM(plays), SUM(playback_ms), SUM(bytes), SUM(inbound_bytes), SUM(outbound_bytes), SUM(sessions), SUM(errors)
		FROM play_buckets
		WHERE bucket_start >= ? AND bucket_start < ?
		GROUP BY node, client
	`, startTime, endTime)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()

	out := []PlayStat{}
	for rows.Next() {
		var stat PlayStat
		if err := rows.Scan(&stat.Node, &stat.Client, &stat.Plays, &stat.PlaybackMillis, &stat.Bytes, &stat.InboundBytes, &stat.OutboundBytes, &stat.Sessions, &stat.Errors); err != nil {
			return nil, 0, 0, err
		}
		stat.Bytes = stat.InboundBytes + stat.OutboundBytes
		out = append(out, stat)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, err
	}

	var proxyPlays, directPlays int64
	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0) FROM play_buckets
		WHERE bucket_start >= ? AND bucket_start < ? AND mode = 'proxy' AND plays > 0
	`, startTime, endTime).Scan(&proxyPlays)
	if err != nil {
		return nil, 0, 0, err
	}

	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(plays), 0) FROM play_buckets
		WHERE bucket_start >= ? AND bucket_start < ? AND mode = 'direct' AND plays > 0
	`, startTime, endTime).Scan(&directPlays)
	if err != nil {
		return nil, 0, 0, err
	}

	return out, proxyPlays, directPlays, nil
}

func (s *Store) PrunePlayBuckets(ctx context.Context, keepDays int) error {
	if keepDays <= 0 {
		keepDays = 3
	}
	cutoff := playbackBucketStart(time.Now().AddDate(0, 0, -keepDays).UnixMilli())
	_, err := s.db.ExecContext(ctx, `DELETE FROM play_buckets WHERE bucket_start < ?`, cutoff)
	return err
}

func (s *Store) PrunePlaybackStates(ctx context.Context, maxAge time.Duration) error {
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	cutoff := time.Now().Add(-maxAge).UnixMilli()
	_, err := s.db.ExecContext(ctx, `DELETE FROM playback_states WHERE updated_at < ?`, cutoff)
	return err
}

func upsertPlayBucket(ctx context.Context, exec sqlExecer, occurredAt int64, node, client, mode string, plays, playbackMillis, bytes, inboundBytes, outboundBytes, sessions, errors int64) error {
	bucketStart := playbackBucketStart(occurredAt)
	_, err := exec.ExecContext(ctx, `
		INSERT INTO play_buckets (bucket_start, node, client, mode, plays, playback_ms, bytes, inbound_bytes, outbound_bytes, sessions, errors, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket_start, node, client, mode) DO UPDATE SET
			plays = plays + excluded.plays,
			playback_ms = playback_ms + excluded.playback_ms,
			bytes = bytes + excluded.bytes,
			inbound_bytes = inbound_bytes + excluded.inbound_bytes,
			outbound_bytes = outbound_bytes + excluded.outbound_bytes,
			sessions = sessions + excluded.sessions,
			errors = errors + excluded.errors,
			updated_at = MAX(play_buckets.updated_at, excluded.updated_at)
	`, bucketStart, node, client, mode, plays, playbackMillis, bytes, inboundBytes, outboundBytes, sessions, errors, occurredAt)
	return err
}

func playbackBucketStart(ts int64) int64 {
	if ts <= 0 {
		return 0
	}
	return ts - ts%playbackBucketMillis
}
