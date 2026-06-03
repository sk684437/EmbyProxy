package capture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

type contextKey struct{}

type Recorder struct {
	cfg   config.Config
	store *storage.Store
	log   *logging.Logger
}

type state struct {
	StartedAt     time.Time
	Meta          map[string]any
	RequestBody   []byte
	ParsedBody    any
	ResponseBody  bytes.Buffer
	ResponseBytes int64
	Truncated     bool
	Suppressed    bool
}

type BodySummary struct {
	Kind      string `json:"kind"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256,omitempty"`
	Text      string `json:"text,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type Record struct {
	ID              string         `json:"id"`
	TS              int64          `json:"ts"`
	Mode            string         `json:"mode"`
	Node            string         `json:"node"`
	AdminAction     string         `json:"adminAction"`
	Stage           string         `json:"stage"`
	Method          string         `json:"method"`
	InboundURL      string         `json:"inboundUrl"`
	InboundHeaders  map[string]any `json:"inboundHeaders"`
	InboundBody     BodySummary    `json:"inboundBody"`
	TargetURL       string         `json:"targetUrl"`
	OutboundHeaders map[string]any `json:"outboundHeaders"`
	Status          int            `json:"status"`
	ResponseHeaders map[string]any `json:"responseHeaders"`
	ResponseBody    BodySummary    `json:"responseBody"`
	ResponseBytes   int64          `json:"responseBytes"`
	DurationMS      float64        `json:"durationMs"`
	Meta            any            `json:"meta"`
	CaseSignature   string         `json:"caseSignature,omitempty"`
}

type captureWriter struct {
	http.ResponseWriter
	state  *state
	status int
	max    int64
}

func New(cfg config.Config, store *storage.Store, log *logging.Logger) *Recorder {
	return &Recorder{cfg: cfg, store: store, log: log}
}

func (r *Recorder) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		captureCfg, err := r.captureConfig(req.Context())
		if err != nil {
			r.log.Warn("traffic", "capture config lookup failed", map[string]any{"error": err.Error()})
			next.ServeHTTP(w, req)
			return
		}
		if !captureCfg.TrafficCaptureEnabled {
			next.ServeHTTP(w, req)
			return
		}
		st := &state{StartedAt: time.Now(), Meta: map[string]any{}}
		req = req.WithContext(context.WithValue(req.Context(), contextKey{}, st))
		cw := &captureWriter{ResponseWriter: w, state: st, status: http.StatusOK, max: captureBodyMax(captureCfg)}
		next.ServeHTTP(cw, req)
		if Suppressed(req) {
			return
		}
		r.appendHTTP(req, cw, captureCfg)
	})
}

func (r *Recorder) captureConfig(ctx context.Context) (storage.SystemConfig, error) {
	fallback := storage.DefaultSystemConfig()
	if r.store == nil {
		return fallback, nil
	}
	return r.store.GetSystemConfig(ctx, fallback)
}

func captureBodyMax(cfg storage.SystemConfig) int64 {
	if cfg.TrafficCaptureBodyMax > 0 {
		return cfg.TrafficCaptureBodyMax
	}
	return storage.DefaultSystemConfig().TrafficCaptureBodyMax
}

func SetMeta(req *http.Request, meta map[string]any) {
	st := State(req)
	if st == nil || meta == nil {
		return
	}
	if st.Meta == nil {
		st.Meta = map[string]any{}
	}
	for key, value := range meta {
		st.Meta[key] = value
	}
}

func RememberRequestBody(req *http.Request, body []byte) {
	st := State(req)
	if st == nil {
		return
	}
	st.RequestBody = append(st.RequestBody[:0], body...)
}

func RememberParsedBody(req *http.Request, value any) {
	st := State(req)
	if st == nil {
		return
	}
	st.ParsedBody = value
}

// Suppress skips persisting the current request in traffic capture output.
func Suppress(req *http.Request) {
	st := State(req)
	if st == nil {
		return
	}
	st.Suppressed = true
}

// Suppressed reports whether the current request should be skipped by capture.
func Suppressed(req *http.Request) bool {
	st := State(req)
	return st != nil && st.Suppressed
}

func State(req *http.Request) *state {
	if req == nil {
		return nil
	}
	st, _ := req.Context().Value(contextKey{}).(*state)
	return st
}

func (w *captureWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *captureWriter) Write(chunk []byte) (int, error) {
	if len(chunk) > 0 {
		w.state.ResponseBytes += int64(len(chunk))
		max := int(w.stateMax())
		if w.state.ResponseBody.Len() < max {
			take := max - w.state.ResponseBody.Len()
			if take > len(chunk) {
				take = len(chunk)
			}
			_, _ = w.state.ResponseBody.Write(chunk[:take])
		}
		if w.state.ResponseBytes > w.stateMax() {
			w.state.Truncated = true
		}
	}
	return w.ResponseWriter.Write(chunk)
}

func (w *captureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (w *captureWriter) stateMax() int64 {
	return captureBodyMax(storage.SystemConfig{TrafficCaptureBodyMax: w.max})
}

func (r *Recorder) appendHTTP(req *http.Request, cw *captureWriter, cfg storage.SystemConfig) {
	st := cw.state
	meta := st.Meta
	responseHeaders := http.Header{}
	for key, values := range cw.Header() {
		responseHeaders[key] = values
	}
	inboundBody := BodySummary{Kind: "none", Bytes: 0}
	if st.ParsedBody != nil {
		b, _ := json.Marshal(st.ParsedBody)
		inboundBody = summarizeBuffer(b, int64(len(b)), req.Header.Get("Content-Type"), false, cfg)
	} else if st.RequestBody != nil {
		inboundBody = summarizeBuffer(st.RequestBody, int64(len(st.RequestBody)), req.Header.Get("Content-Type"), false, cfg)
	}
	record := Record{
		ID:              requestID(req, r.log),
		TS:              time.Now().UnixMilli(),
		Mode:            stringMeta(meta, "mode", inferMode(req, meta)),
		Node:            stringMeta(meta, "node", ""),
		AdminAction:     stringMeta(meta, "adminAction", ""),
		Stage:           stringMeta(meta, "stage", ""),
		Method:          strings.ToUpper(req.Method),
		InboundURL:      inboundURL(req, meta),
		InboundHeaders:  headersToMap(req.Header),
		InboundBody:     inboundBody,
		TargetURL:       stringMeta(meta, "targetUrl", ""),
		OutboundHeaders: headersToMap(headerMeta(meta["outboundHeaders"])),
		Status:          cw.status,
		ResponseHeaders: headersToMap(responseHeaders),
		ResponseBody:    summarizeBuffer(st.ResponseBody.Bytes(), st.ResponseBytes, responseHeaders.Get("Content-Type"), st.Truncated || cw.status == http.StatusPartialContent || responseHeaders.Get("Content-Range") != "", cfg),
		ResponseBytes:   st.ResponseBytes,
		DurationMS:      float64(time.Since(st.StartedAt).Microseconds()) / 1000,
		Meta:            meta["meta"],
	}
	r.appendRecord(record, cfg)
}

func (r *Recorder) appendRecord(record Record, cfg storage.SystemConfig) {
	file := r.captureFilePath(cfg)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		r.log.Warn("traffic", "capture mkdir failed", map[string]any{"error": err.Error()})
		return
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		r.log.Warn("traffic", "capture open failed", map[string]any{"error": err.Error()})
		return
	}
	defer f.Close()
	_ = f.Chmod(0600)
	b, err := json.Marshal(record)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
}

func (r *Recorder) captureFilePath(cfg storage.SystemConfig) string {
	file := safeCaptureFile(cfg.TrafficCaptureFile)
	if file == "" {
		file = safeCaptureFile(storage.DefaultSystemConfig().TrafficCaptureFile)
	}
	if file == "" {
		file = filepath.Join("data", "traffic-captures.jsonl")
	}
	return filepath.Join(r.cfg.CWD, file)
}

func safeCaptureFile(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	normalized := strings.NewReplacer("\\", string(filepath.Separator), "/", string(filepath.Separator)).Replace(value)
	cleaned := filepath.Clean(normalized)
	if cleaned == "" || cleaned == "." || cleaned == "data" {
		return ""
	}
	if filepath.IsAbs(cleaned) || filepath.VolumeName(cleaned) != "" {
		return ""
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return ""
	}
	if !strings.HasPrefix(cleaned, "data"+string(filepath.Separator)) {
		return ""
	}
	return cleaned
}

func summarizeBuffer(buf []byte, bytesLen int64, contentType string, truncated bool, cfg storage.SystemConfig) BodySummary {
	if bytesLen == 0 {
		return BodySummary{Kind: "none", Bytes: 0}
	}
	max := captureBodyMax(cfg)
	if truncated || bytesLen > max {
		return BodySummary{Kind: "truncated", Bytes: bytesLen, Truncated: true}
	}
	sha := sha256.Sum256(buf)
	base := contentTypeBase(contentType)
	if !isTextContentType(base, cfg) {
		return BodySummary{Kind: "binary", Bytes: bytesLen, SHA256: hex.EncodeToString(sha[:])}
	}
	text := string(buf)
	kind := "text"
	if strings.Contains(base, "json") {
		kind = "json"
	}
	return BodySummary{Kind: kind, Bytes: bytesLen, SHA256: hex.EncodeToString(sha[:]), Text: text}
}

func inferMode(req *http.Request, meta map[string]any) string {
	if v := stringMeta(meta, "mode", ""); v != "" {
		return v
	}
	path := req.URL.Path
	if strings.HasPrefix(path, "/admin") {
		return "admin"
	}
	if strings.HasPrefix(path, "/static") {
		return "static"
	}
	if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return "ws"
	}
	return "proxy"
}

func inboundURL(req *http.Request, meta map[string]any) string {
	return req.URL.RequestURI()
}

func requestID(req *http.Request, log *logging.Logger) string {
	if id := req.Context().Value("requestID"); id != nil {
		if s, ok := id.(string); ok && s != "" {
			return s
		}
	}
	return log.NextRequestID("traffic")
}

func headersToMap(headers http.Header) map[string]any {
	out := map[string]any{}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lower := strings.ToLower(key)
		value := strings.Join(headers.Values(key), ", ")
		out[lower] = value
	}
	return out
}

func headerMeta(value any) http.Header {
	headers := http.Header{}
	switch v := value.(type) {
	case http.Header:
		for key, values := range v {
			headers[key] = append([]string(nil), values...)
		}
	case map[string]string:
		for key, val := range v {
			headers.Set(key, val)
		}
	case map[string][]string:
		for key, values := range v {
			headers[key] = append([]string(nil), values...)
		}
	}
	return headers
}

func isTextContentType(base string, cfg storage.SystemConfig) bool {
	if strings.HasPrefix(base, "text/") {
		return true
	}
	if strings.HasSuffix(base, "+json") || strings.HasSuffix(base, "+xml") {
		return true
	}
	for _, item := range strings.Split(cfg.TrafficCaptureTextTypes, ",") {
		if strings.TrimSpace(strings.ToLower(item)) == base {
			return true
		}
	}
	return false
}

func contentTypeBase(value string) string {
	return strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
}

func stringMeta(meta map[string]any, key, fallback string) string {
	if meta == nil {
		return fallback
	}
	if value, ok := meta[key]; ok && value != nil {
		return strings.TrimSpace(fmt.Sprint(value))
	}
	return fallback
}

func ReadJSONL(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	s.Buffer(buf, 32*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, s.Err()
}

func DrainAndRemember(req *http.Request, max int64) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	var reader io.Reader = req.Body
	if max > 0 {
		reader = io.LimitReader(req.Body, max+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	RememberRequestBody(req, body)
	return body, nil
}
