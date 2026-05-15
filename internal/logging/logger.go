package logging

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var levels = map[string]int{
	"silent": 0,
	"error":  1,
	"warn":   2,
	"info":   3,
	"debug":  4,
}

var sensitiveQueryRE = regexp.MustCompile(`(?i)(token|api[_-]?key|access[_-]?token|auth|authorization|password|secret|session)`)

type Logger struct {
	level     atomic.Int64
	accessLog atomic.Bool
	seq       atomic.Uint64
}

func New(level string, accessLog bool) *Logger {
	l := &Logger{}
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

func (l *Logger) Debug(scope, msg string, meta map[string]any) { l.write("debug", scope, msg, meta) }
func (l *Logger) Info(scope, msg string, meta map[string]any)  { l.write("info", scope, msg, meta) }
func (l *Logger) Warn(scope, msg string, meta map[string]any)  { l.write("warn", scope, msg, meta) }
func (l *Logger) Error(scope, msg string, meta map[string]any) { l.write("error", scope, msg, meta) }

func (l *Logger) write(level, scope, msg string, meta map[string]any) {
	level = normalizeLevel(level)
	if !l.Enabled(level) {
		return
	}
	parts := []string{time.Now().UTC().Format(time.RFC3339), strings.ToUpper(level), "[" + scope + "]"}
	if clean := cleanString(msg, 512); clean != "" {
		parts = append(parts, clean)
	}
	if formatted := formatMeta(meta); formatted != "" {
		parts = append(parts, formatted)
	}
	line := strings.Join(parts, " ")
	if level == "error" || level == "warn" {
		fmt.Fprintln(os.Stderr, line)
		return
	}
	fmt.Fprintln(os.Stdout, line)
}

func RedactURL(raw string) string {
	value := cleanString(raw, 512)
	if value == "" {
		return ""
	}
	hasOrigin := regexp.MustCompile(`(?i)^https?://`).MatchString(value)
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
		if value != nil && fmt.Sprint(value) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+formatValue(meta[key]))
	}
	return strings.Join(parts, " ")
}

func formatValue(value any) string {
	s := cleanString(fmt.Sprint(value), 512)
	if s == "" {
		return ""
	}
	if regexp.MustCompile(`^[A-Za-z0-9_./:@-]+$`).MatchString(s) {
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
