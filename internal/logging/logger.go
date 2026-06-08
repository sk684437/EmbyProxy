package logging

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"embyproxy/internal/localtime"
)

const (
	DefaultBufferCapacity      = 2000
	DefaultHistoryEntriesFile  = 2000
	DefaultHistoryRotatedFiles = 10
	logHistoryBufferSize       = 64 * 1024
	logHistoryFlushInterval    = time.Second
)

var levels = map[string]int{
	"silent": 0,
	"error":  1,
	"warn":   2,
	"info":   3,
	"debug":  4,
}

var (
	sensitiveQueryRE  = regexp.MustCompile(`(?i)(token|api[_-]?key|access[_-]?token|auth|authorization|password|secret|session)`)
	httpURLRE         = regexp.MustCompile(`(?i)^https?://`)
	embeddedHTTPURLRE = regexp.MustCompile(`(?i)https?://[^\s"'<>()]+`)
	safeLogValueRE    = regexp.MustCompile(`^[A-Za-z0-9_./:@-]+$`)
)

var metaFieldOrder = map[string]int{
	"event":              10,
	"id":                 20,
	"method":             30,
	"uri":                40,
	"ip":                 50,
	"node":               60,
	"nodeTarget":         70,
	"target":             80,
	"location":           90,
	"range":              100,
	"contentRange":       110,
	"imageCache":         120,
	"bytes":              130,
	"contentLen":         140,
	"copiedBytes":        150,
	"readBytes":          160,
	"writeBytes":         170,
	"readCalls":          180,
	"writeCalls":         190,
	"responseReadyMs":    200,
	"targetAttemptMs":    210,
	"bodyMs":             220,
	"copyMs":             230,
	"totalMs":            240,
	"firstReadMs":        250,
	"firstReadStatus":    260,
	"lastReadMs":         270,
	"lastWriteMs":        280,
	"upgradeMs":          290,
	"addr":               300,
	"db":                 310,
	"profile":            320,
	"label":              330,
	"client":             340,
	"version":            350,
	"commit":             360,
	"builtAt":            370,
	"device":             380,
	"deviceId":           390,
	"userAgent":          400,
	"day":                410,
	"count":              420,
	"reason":             900,
	"side":               910,
	"contextErr":         920,
	"bodyCopySide":       930,
	"bodyCopyContextErr": 940,
	"bodyCopyError":      950,
	"error":              960,
}

type Logger struct {
	level     atomic.Int64
	accessLog atomic.Bool
	seq       atomic.Uint64
	// mu keeps buffer and history on the same side of a clear boundary.
	mu      sync.Mutex
	buffer  *logBuffer
	history *logHistory
}

type LogEntry struct {
	ID      uint64 `json:"id"`
	Time    string `json:"time"`
	Level   string `json:"level"`
	Scope   string `json:"scope"`
	Message string `json:"message"`
	Line    string `json:"line"`
}

type logBuffer struct {
	mu       sync.Mutex
	next     uint64
	start    int
	entries  []LogEntry
	capacity int
}

type LogPage struct {
	Entries  []LogEntry
	HasOlder bool
	History  bool
}

type logHistory struct {
	mu              sync.Mutex
	path            string
	entriesPerFile  int
	maxFiles        int
	entryCount      int
	retainedEntries int
	oldestID        uint64
	file            *os.File
	writer          *bufio.Writer
	closed          bool
	done            chan struct{}
}

func New(level string, accessLog bool) *Logger {
	l := &Logger{buffer: newLogBuffer(DefaultBufferCapacity)}
	l.Configure(level, accessLog)
	return l
}

// Configure updates logging behavior for future writes.
func (l *Logger) Configure(level string, accessLog bool) {
	l.level.Store(int64(levels[normalizeLevel(level)]))
	l.accessLog.Store(accessLog)
}

func (l *Logger) NextRequestID(prefix string) string {
	if prefix == "" {
		prefix = "req"
	}
	n := l.seq.Add(1)
	return fmt.Sprintf("%s-%s-%x", prefix, strconv36(time.Now().UnixMilli()), n)
}

func (l *Logger) AccessEnabled() bool {
	return l.accessLog.Load() && l.Enabled("info")
}

func (l *Logger) Enabled(level string) bool {
	return int(l.level.Load()) >= levels[normalizeLevel(level)]
}

func (l *Logger) Entries(limit int) []LogEntry {
	if l == nil || l.buffer == nil {
		return nil
	}
	return l.buffer.Entries(limit)
}

// Clear removes buffered and persisted console log entries.
func (l *Logger) Clear() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.history != nil {
		if err := l.history.reset(); err != nil {
			return err
		}
	}
	if l.buffer != nil {
		l.buffer.Clear()
	}
	return nil
}

func (l *Logger) BufferCapacity() int {
	if l == nil || l.buffer == nil {
		return 0
	}
	return l.buffer.Capacity()
}

func (l *Logger) EnableHistory(path string, entriesPerFile, maxFiles int) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.history != nil {
		if err := l.history.Close(); err != nil {
			return err
		}
		l.history = nil
	}
	history, err := newLogHistory(path, entriesPerFile, maxFiles)
	if err != nil {
		return err
	}
	l.history = history
	return nil
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.history == nil {
		return nil
	}
	return l.history.Close()
}

func (l *Logger) Page(limit int, before uint64) LogPage {
	if l == nil {
		return LogPage{}
	}
	if l.buffer != nil {
		entries, hasOlder := l.buffer.EntriesBefore(limit, before)
		if before == 0 || len(entries) > 0 {
			if l.history != nil {
				if len(entries) > 0 && l.history.HasBefore(entries[0].ID) {
					hasOlder = true
				}
				return LogPage{Entries: entries, HasOlder: hasOlder, History: true}
			}
			return LogPage{Entries: entries, HasOlder: hasOlder}
		}
	}
	if l.history != nil {
		entries, hasOlder, err := l.history.Page(limit, before)
		if err == nil {
			return LogPage{Entries: entries, HasOlder: hasOlder, History: true}
		}
	}
	if l.buffer == nil {
		return LogPage{}
	}
	entries, hasOlder := l.buffer.EntriesBefore(limit, before)
	return LogPage{Entries: entries, HasOlder: hasOlder}
}

func (l *Logger) Debug(scope, msg string, meta map[string]any) { l.write("debug", scope, msg, meta) }
func (l *Logger) Info(scope, msg string, meta map[string]any)  { l.write("info", scope, msg, meta) }
func (l *Logger) Warn(scope, msg string, meta map[string]any)  { l.write("warn", scope, msg, meta) }
func (l *Logger) Error(scope, msg string, meta map[string]any) { l.write("error", scope, msg, meta) }

func (l *Logger) write(level, scope, msg string, meta map[string]any) {
	level = normalizeLevel(level)
	if !l.Enabled(level) {
		return
	}
	status := promotedMetaValue(meta, "status")
	parts := []string{localtime.RFC3339(time.Now()), "[" + strings.ToUpper(level) + "]"}
	if status != "" {
		parts = append(parts, "["+status+"]")
	}
	parts = append(parts, "["+scope+"]")
	if clean := RedactText(msg); clean != "" && promotedMetaValue(meta, "event") == "" {
		parts = append(parts, clean)
	}
	if formatted := formatMeta(meta); formatted != "" {
		parts = append(parts, formatted)
	}
	line := strings.Join(parts, " ")
	entry := LogEntry{Time: parts[0], Level: level, Scope: scope, Message: RedactText(msg), Line: line}
	l.mu.Lock()
	if l.buffer != nil {
		entry = l.buffer.Append(entry)
	}
	if l.history != nil {
		_ = l.history.Append(entry)
	}
	l.mu.Unlock()
	if level == "error" || level == "warn" {
		fmt.Fprintln(os.Stderr, line)
		return
	}
	fmt.Fprintln(os.Stdout, line)
}

func newLogBuffer(capacity int) *logBuffer {
	if capacity < 1 {
		capacity = 1
	}
	return &logBuffer{capacity: capacity, entries: make([]LogEntry, 0, capacity)}
}

func (b *logBuffer) Append(entry LogEntry) LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	entry.ID = b.next
	if len(b.entries) < b.capacity {
		b.entries = append(b.entries, entry)
		return entry
	}
	b.entries[b.start] = entry
	b.start = (b.start + 1) % b.capacity
	return entry
}

func (b *logBuffer) Entries(limit int) []LogEntry {
	entries, _ := b.EntriesBefore(limit, 0)
	return entries
}

func (b *logBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next = 0
	b.start = 0
	b.entries = b.entries[:0]
}

func (b *logBuffer) EntriesBefore(limit int, before uint64) ([]LogEntry, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	total := len(b.entries)
	if limit <= 0 || limit > total {
		limit = total
	}
	all := make([]LogEntry, 0, total)
	for i := 0; i < total; i++ {
		idx := (b.start + i) % b.capacity
		entry := b.entries[idx]
		if before == 0 || entry.ID < before {
			all = append(all, entry)
		}
	}
	if limit <= 0 || limit > len(all) {
		limit = len(all)
	}
	hasOlder := len(all) > limit
	if hasOlder {
		all = all[len(all)-limit:]
	}
	return all, hasOlder
}

func (b *logBuffer) Capacity() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capacity
}

func newLogHistory(path string, entriesPerFile, maxFiles int) (*logHistory, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("log history path is empty")
	}
	if entriesPerFile < 1 {
		entriesPerFile = DefaultHistoryEntriesFile
	}
	if maxFiles < 1 {
		maxFiles = DefaultHistoryRotatedFiles
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	h := &logHistory{path: path, entriesPerFile: entriesPerFile, maxFiles: maxFiles, done: make(chan struct{})}
	if err := h.reset(); err != nil {
		return nil, err
	}
	go h.flushLoop()
	return h, nil
}

func (h *logHistory) reset() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.closeWriterLocked(); err != nil {
		return err
	}
	for _, path := range h.pathsNewestFirst() {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	h.entryCount = 0
	h.retainedEntries = 0
	h.oldestID = 0
	return nil
}

func (h *logHistory) Append(entry LogEntry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	if h.entryCount >= h.entriesPerFile {
		if err := h.rotateLocked(); err != nil {
			return err
		}
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := h.ensureWriterLocked(); err != nil {
		return err
	}
	if _, err := h.writer.Write(b); err != nil {
		return err
	}
	if err := h.writer.WriteByte('\n'); err != nil {
		return err
	}
	h.entryCount++
	h.retainedEntries++
	if h.oldestID == 0 || h.retainedEntries == 1 {
		h.oldestID = entry.ID
	}
	return nil
}

func (h *logHistory) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	close(h.done)
	return h.closeWriterLocked()
}

func (h *logHistory) flushLoop() {
	ticker := time.NewTicker(logHistoryFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.mu.Lock()
			if h.closed {
				h.mu.Unlock()
				return
			}
			_ = h.flushWriterLocked()
			h.mu.Unlock()
		case <-h.done:
			return
		}
	}
}

func (h *logHistory) ensureWriterLocked() error {
	if h.writer != nil && h.file != nil {
		return nil
	}
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	h.file = f
	h.writer = bufio.NewWriterSize(f, logHistoryBufferSize)
	return nil
}

func (h *logHistory) flushWriterLocked() error {
	if h.writer == nil {
		return nil
	}
	if err := h.writer.Flush(); err != nil {
		return err
	}
	return nil
}

func (h *logHistory) closeWriterLocked() error {
	var firstErr error
	if h.writer != nil {
		if err := h.writer.Flush(); err != nil {
			firstErr = err
		}
		h.writer = nil
	}
	if h.file != nil {
		if err := h.file.Close(); firstErr == nil && err != nil {
			firstErr = err
		}
		h.file = nil
	}
	return firstErr
}

func (h *logHistory) HasBefore(id uint64) bool {
	if h == nil || id == 0 {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.retainedEntries > 0 && h.oldestID > 0 && h.oldestID < id
}

func (h *logHistory) Page(limit int, before uint64) ([]LogEntry, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.flushWriterLocked(); err != nil {
		return nil, false, err
	}
	if limit <= 0 {
		limit = h.entriesPerFile
	}
	entries := []LogEntry{}
	for _, path := range h.pathsOldestFirst() {
		if err := readLogEntries(path, before, &entries); err != nil {
			return nil, false, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	if limit > len(entries) {
		limit = len(entries)
	}
	hasOlder := len(entries) > limit
	if hasOlder {
		entries = entries[len(entries)-limit:]
	}
	return entries, hasOlder, nil
}

func (h *logHistory) rotateLocked() error {
	if err := h.closeWriterLocked(); err != nil {
		return err
	}
	if h.maxFiles <= 1 {
		if err := os.Remove(h.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		h.entryCount = 0
		h.retainedEntries = 0
		h.oldestID = 0
		return nil
	}
	oldest := rotatedLogPath(h.path, h.maxFiles-1)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return err
	}
	if capacity := h.entriesPerFile * h.maxFiles; h.retainedEntries >= capacity {
		h.retainedEntries -= h.entriesPerFile
		h.oldestID += uint64(h.entriesPerFile)
	}
	for i := h.maxFiles - 2; i >= 1; i-- {
		from := rotatedLogPath(h.path, i)
		to := rotatedLogPath(h.path, i+1)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(h.path, rotatedLogPath(h.path, 1)); err != nil && !os.IsNotExist(err) {
		return err
	}
	h.entryCount = 0
	return nil
}

func (h *logHistory) pathsNewestFirst() []string {
	paths := []string{h.path}
	for i := 1; i < h.maxFiles; i++ {
		paths = append(paths, rotatedLogPath(h.path, i))
	}
	return paths
}

func (h *logHistory) pathsOldestFirst() []string {
	paths := make([]string, 0, h.maxFiles)
	for i := h.maxFiles - 1; i >= 1; i-- {
		paths = append(paths, rotatedLogPath(h.path, i))
	}
	paths = append(paths, h.path)
	return paths
}

func rotatedLogPath(path string, index int) string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return base + "." + strconv.Itoa(index) + ext
}

func readLogEntries(path string, before uint64, out *[]LogEntry) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.ID == 0 || (before > 0 && entry.ID >= before) {
			continue
		}
		*out = append(*out, entry)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

func RedactURL(raw string) string {
	value := cleanString(raw, 512)
	if value == "" {
		return ""
	}
	hasOrigin := httpURLRE.MatchString(value)
	u, err := url.Parse(value)
	if err == nil {
		if !hasOrigin {
			u, err = url.Parse("http://local" + ensureLeadingSlash(value))
		}
		if err == nil {
			out := u.EscapedPath()
			if out == "" {
				out = "/"
			}
			out += redactQuery(u.RawQuery)
			if hasOrigin {
				return u.Scheme + "://" + u.Host + out
			}
			return out
		}
	}
	idx := strings.IndexByte(value, '#')
	if idx >= 0 {
		value = value[:idx]
	}
	q := strings.IndexByte(value, '?')
	if q < 0 {
		return value
	}
	return value[:q] + redactQuery(value[q+1:])
}

func RedactText(raw string) string {
	value := cleanString(raw, 512)
	if value == "" {
		return ""
	}
	return embeddedHTTPURLRE.ReplaceAllStringFunc(value, RedactURL)
}

func RedactProxyURL(raw, nodeName, secret string) string {
	redacted := RedactURL(raw)
	node := strings.ToLower(strings.TrimSpace(nodeName))
	secret = strings.TrimSpace(secret)
	if node == "" || secret == "" || redacted == "" {
		return redacted
	}
	variants := []string{secret, url.PathEscape(secret)}
	for _, v := range variants {
		marker := "/" + node + "/" + v
		if strings.HasPrefix(strings.ToLower(redacted), strings.ToLower(marker)) {
			return "/" + node + "/<secret>" + redacted[len(marker):]
		}
	}
	return redacted
}

func FormatTarget(target string) string {
	u, err := url.Parse(target)
	if err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return RedactURL(target)
}

func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		key := part
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			key = part[:idx]
		}
		decoded, err := url.QueryUnescape(key)
		if err != nil {
			decoded = key
		}
		if sensitiveQueryRE.MatchString(decoded) {
			out = append(out, key+"=<redacted>")
		} else {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return "?" + strings.Join(out, "&")
}

func ensureLeadingSlash(value string) string {
	if strings.HasPrefix(value, "/") {
		return value
	}
	return "/" + value
}

func cleanString(value string, maxLen int) string {
	replacer := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")
	s := strings.TrimSpace(replacer.Replace(value))
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func formatMeta(meta map[string]any) string {
	if len(meta) == 0 {
		return ""
	}
	keys := make([]string, 0, len(meta))
	for key, value := range meta {
		if key == "status" {
			continue
		}
		if value != nil && fmt.Sprint(value) != "" {
			keys = append(keys, key)
		}
	}
	sortMetaKeys(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+formatValue(meta[key]))
	}
	return strings.Join(parts, " ")
}

func sortMetaKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		left, leftOK := metaFieldOrder[keys[i]]
		right, rightOK := metaFieldOrder[keys[j]]
		if leftOK || rightOK {
			if !leftOK {
				return false
			}
			if !rightOK {
				return true
			}
			if left != right {
				return left < right
			}
		}
		return keys[i] < keys[j]
	})
}

func promotedMetaValue(meta map[string]any, key string) string {
	if len(meta) == 0 {
		return ""
	}
	value, ok := meta[key]
	if !ok || value == nil || fmt.Sprint(value) == "" {
		return ""
	}
	return formatValue(value)
}

func formatValue(value any) string {
	s := RedactText(fmt.Sprint(value))
	if s == "" {
		return ""
	}
	if safeLogValueRE.MatchString(s) {
		return s
	}
	return fmt.Sprintf("%q", s)
}

func normalizeLevel(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if _, ok := levels[v]; ok {
		return v
	}
	return "info"
}

func strconv36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%36]
		n /= 36
	}
	return string(b[i:])
}
