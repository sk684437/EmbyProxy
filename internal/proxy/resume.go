package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	streamResumeMaxAttempts = 2
	streamResumeDrainLimit  = 256 * 1024
	streamResumeBufferSize  = 128 * 1024
)

type upstreamClientContextKey struct{}
type streamResumeSourceContextKey struct{}

type streamResumePlan struct {
	initialStatus int
	rangeStart    int64
	rangeEnd      int64
	resourceSize  int64
	validator     streamResumeValidator
}

type streamResumeValidator struct {
	etag         string
	lastModified string
	ifRange      string
}

type streamResumeProgress struct {
	attempts     int
	resumedBytes int64
	firstFrom    int64
	err          error
	resumeErr    bool
}

func attachUpstreamClient(res *http.Response, client *http.Client) {
	if res == nil || res.Request == nil || client == nil {
		return
	}
	res.Request = res.Request.WithContext(context.WithValue(res.Request.Context(), upstreamClientContextKey{}, client))
}

func markStreamResumeCandidate(res *http.Response, source string) {
	if res == nil || res.Request == nil {
		return
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "stream"
	}
	res.Request = res.Request.WithContext(context.WithValue(res.Request.Context(), streamResumeSourceContextKey{}, source))
}

func streamResumeSource(res *http.Response) string {
	if res == nil || res.Request == nil {
		return ""
	}
	source, _ := res.Request.Context().Value(streamResumeSourceContextKey{}).(string)
	return strings.TrimSpace(source)
}

func upstreamClientForResponse(res *http.Response) *http.Client {
	if res == nil || res.Request == nil {
		return nil
	}
	client, _ := res.Request.Context().Value(upstreamClientContextKey{}).(*http.Client)
	return client
}

func (h *Handler) streamResumePlan(r *http.Request, res *http.Response) (streamResumePlan, bool) {
	if streamResumeMaxAttempts < 1 || r == nil || res == nil || res.Body == nil {
		return streamResumePlan{}, false
	}
	if r.Method != http.MethodGet || streamResumeSource(res) == "" {
		return streamResumePlan{}, false
	}
	if res.Request == nil || res.Request.URL == nil || upstreamClientForResponse(res) == nil {
		return streamResumePlan{}, false
	}
	if res.Uncompressed || strings.TrimSpace(res.Header.Get("Content-Encoding")) != "" {
		return streamResumePlan{}, false
	}
	if !streamResumeResponseLooksLikeMedia(res) || !streamResumeAcceptsBytes(res.Header) {
		return streamResumePlan{}, false
	}
	validator, ok := newStreamResumeValidator(res.Header)
	if !ok {
		return streamResumePlan{}, false
	}

	switch res.StatusCode {
	case http.StatusOK:
		requestRange := strings.TrimSpace(res.Request.Header.Get("Range"))
		if requestRange != "" && !streamResumeInitialFullRange(requestRange) {
			return streamResumePlan{}, false
		}
		length := responseContentLength(res)
		if length <= 0 {
			return streamResumePlan{}, false
		}
		return streamResumePlan{
			initialStatus: res.StatusCode,
			rangeStart:    0,
			rangeEnd:      length - 1,
			resourceSize:  length,
			validator:     validator,
		}, true
	case http.StatusPartialContent:
		if !streamResumeSingleByteRange(res.Request.Header.Get("Range")) || streamResumeMultipart(res.Header) {
			return streamResumePlan{}, false
		}
		start, end, total, ok := parseStreamContentRange(res.Header.Get("Content-Range"))
		if !ok || start < 0 || end < start || total <= end {
			return streamResumePlan{}, false
		}
		return streamResumePlan{
			initialStatus: res.StatusCode,
			rangeStart:    start,
			rangeEnd:      end,
			resourceSize:  total,
			validator:     validator,
		}, true
	default:
		return streamResumePlan{}, false
	}
}

func (h *Handler) copyResponseBodyWithResume(w http.ResponseWriter, r *http.Request, res *http.Response, plan streamResumePlan) (bodyCopyStats, error) {
	started := time.Now()
	reader := &bodyCopyReader{started: started}
	writer := &bodyCopyWriter{writer: w}
	progress := streamResumeProgress{firstFrom: -1}
	expectedBytes := plan.responseLength()
	var sentBytes int64
	current := res
	readErr := error(nil)

	buf := make([]byte, streamResumeBufferSize)
	for {
		remaining := expectedBytes - sentBytes
		if remaining <= 0 {
			closeResponseBody(current)
			break
		}
		reader.reader = io.LimitReader(current.Body, remaining)
		n, chunkReadErr, writeErr := copyStreamResumeChunk(writer, reader, buf)
		sentBytes += n
		if progress.attempts > 0 {
			progress.resumedBytes += n
		}
		if writeErr != nil {
			progress.err = writeErr
			closeResponseBody(current)
			readErr = writeErr
			break
		}
		if sentBytes >= expectedBytes {
			closeResponseBody(current)
			break
		}
		if errors.Is(chunkReadErr, io.EOF) {
			chunkReadErr = io.ErrUnexpectedEOF
		}
		if !streamResumeReadError(r, chunkReadErr) {
			progress.err = chunkReadErr
			closeResponseBody(current)
			readErr = chunkReadErr
			break
		}
		if progress.attempts >= streamResumeMaxAttempts {
			progress.err = fmt.Errorf("stream resume attempts exhausted: %w", chunkReadErr)
			progress.resumeErr = true
			closeResponseBody(current)
			readErr = progress.err
			break
		}

		nextStart := plan.rangeStart + sentBytes
		if progress.firstFrom < 0 {
			progress.firstFrom = nextStart
		}
		progress.attempts++
		nextResp, err := h.resumeStreamResponse(current, plan, nextStart)
		drainAndCloseResponseBody(current)
		if err != nil {
			progress.err = err
			progress.resumeErr = true
			readErr = err
			break
		}
		current = nextResp
	}

	stats := bodyCopyStats{readBytes: reader.bytes, writeBytes: writer.bytes}
	setBodyCopyFirstReadAccessLogFields(requestContext(r), reader, false)
	setStreamResumeAccessLogFields(requestContext(r), progress)
	if readErr != nil || requestContextErr(r) != nil {
		h.logBodyCopyIssue(r, res, writer.bytes, readErr, requestContextErr(r), time.Since(started), reader, writer)
		return stats, readErr
	}
	return stats, nil
}

func (h *Handler) resumeStreamResponse(current *http.Response, plan streamResumePlan, nextStart int64) (*http.Response, error) {
	client := upstreamClientForResponse(current)
	if client == nil {
		return nil, errors.New("stream resume missing upstream client")
	}
	nextReq, err := newStreamResumeRequest(current.Request, plan, nextStart)
	if err != nil {
		return nil, err
	}
	nextResp, err := client.Do(nextReq)
	if err != nil {
		return nil, err
	}
	attachUpstreamClient(nextResp, client)
	markStreamResumeCandidate(nextResp, streamResumeSource(current))
	if err := validateStreamResumeResponse(nextResp, plan, nextStart); err != nil {
		closeResponseBody(nextResp)
		return nil, err
	}
	return nextResp, nil
}

func copyStreamResumeChunk(writer *bodyCopyWriter, reader *bodyCopyReader, buf []byte) (int64, error, error) {
	var written int64
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			writeN, writeErr := writer.Write(buf[:n])
			written += int64(writeN)
			if writeErr != nil {
				return written, nil, writeErr
			}
			if writeN != n {
				return written, nil, io.ErrShortWrite
			}
		}
		if readErr != nil {
			return written, readErr, nil
		}
	}
}

func newStreamResumeRequest(base *http.Request, plan streamResumePlan, nextStart int64) (*http.Request, error) {
	if base == nil || base.URL == nil {
		return nil, errors.New("stream resume missing base request")
	}
	out := base.Clone(base.Context())
	out.Body = nil
	out.GetBody = nil
	out.ContentLength = 0
	out.RequestURI = ""
	out.Header = base.Header.Clone()
	out.Header.Del("Content-Length")
	out.Header.Set("Accept-Encoding", "identity")
	out.Header.Set("Range", plan.resumeRange(nextStart))
	if plan.validator.ifRange != "" {
		out.Header.Set("If-Range", plan.validator.ifRange)
	}
	if out.Host == "" && out.URL != nil {
		out.Host = out.URL.Host
	}
	return out, nil
}

func validateStreamResumeResponse(resp *http.Response, plan streamResumePlan, nextStart int64) error {
	if resp == nil {
		return errors.New("stream resume response missing")
	}
	if resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("stream resume unexpected status %d", resp.StatusCode)
	}
	if resp.Uncompressed || strings.TrimSpace(resp.Header.Get("Content-Encoding")) != "" {
		return errors.New("stream resume response was decoded")
	}
	if streamResumeMultipart(resp.Header) {
		return errors.New("stream resume response returned multipart ranges")
	}
	if !plan.validator.matches(resp.Header) {
		return errors.New("stream resume validator changed")
	}
	start, end, total, ok := parseStreamContentRange(resp.Header.Get("Content-Range"))
	if !ok {
		return errors.New("stream resume response missing valid content range")
	}
	if start != nextStart || end != plan.rangeEnd || total != plan.resourceSize {
		return errors.New("stream resume content range mismatch")
	}
	if length := responseContentLength(resp); length > 0 && length != plan.rangeEnd-nextStart+1 {
		return errors.New("stream resume content length mismatch")
	}
	return nil
}

func newStreamResumeValidator(header http.Header) (streamResumeValidator, bool) {
	etag := strings.TrimSpace(streamResumeHeader(header, "ETag"))
	lastModified := strings.TrimSpace(streamResumeHeader(header, "Last-Modified"))
	if etag != "" {
		if strings.HasPrefix(strings.ToUpper(etag), "W/") {
			return streamResumeValidator{}, false
		}
		return streamResumeValidator{etag: etag, ifRange: etag}, true
	}
	if lastModified != "" {
		modifiedAt, errModified := http.ParseTime(lastModified)
		date, errDate := http.ParseTime(strings.TrimSpace(streamResumeHeader(header, "Date")))
		if errModified == nil && errDate == nil && !date.Before(modifiedAt.Add(time.Second)) {
			return streamResumeValidator{lastModified: lastModified, ifRange: lastModified}, true
		}
	}
	return streamResumeValidator{}, false
}

func (v streamResumeValidator) matches(header http.Header) bool {
	if v.etag != "" {
		return strings.TrimSpace(streamResumeHeader(header, "ETag")) == v.etag
	}
	if v.lastModified != "" {
		return strings.TrimSpace(streamResumeHeader(header, "Last-Modified")) == v.lastModified
	}
	return false
}

func streamResumeHeader(header http.Header, name string) string {
	if header == nil {
		return ""
	}
	if value := header.Get(name); value != "" {
		return value
	}
	for key, values := range header {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func (p streamResumePlan) responseLength() int64 {
	return p.rangeEnd - p.rangeStart + 1
}

func (p streamResumePlan) resumeRange(nextStart int64) string {
	if p.initialStatus == http.StatusOK {
		return "bytes=" + strconv.FormatInt(nextStart, 10) + "-"
	}
	return "bytes=" + strconv.FormatInt(nextStart, 10) + "-" + strconv.FormatInt(p.rangeEnd, 10)
}

func streamResumeResponseLooksLikeMedia(res *http.Response) bool {
	if res == nil {
		return false
	}
	source := streamResumeSource(res)
	contentType := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Type")))
	if streamResumeManifestContentType(contentType) || strings.Contains(contentType, "application/json") || strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "xml") || strings.HasPrefix(contentType, "image/") {
		return false
	}
	if res.Request != nil && res.Request.URL != nil {
		path := strings.ToLower(res.Request.URL.Path)
		if strings.Contains(path, "/sessions/playing") || m3u8PathRE.MatchString(path) || strings.HasSuffix(path, ".mpd") {
			return false
		}
		if streamingRE.MatchString(path) || playbackMediaExtRE.MatchString(path) || strings.Contains(path, "/videos/") || strings.Contains(path, "/audio/") || strings.Contains(path, "/hls/") || strings.Contains(path, "/dash/") {
			return true
		}
	}
	if source == "playback" || source == "stream" {
		return true
	}
	return strings.HasPrefix(contentType, "video/") || strings.HasPrefix(contentType, "audio/") || strings.Contains(contentType, "octet-stream")
}

func streamResumeManifestContentType(contentType string) bool {
	return strings.Contains(contentType, "application/vnd.apple.mpegurl") ||
		strings.Contains(contentType, "application/x-mpegurl") ||
		strings.Contains(contentType, "application/dash+xml")
}

func streamResumeAcceptsBytes(header http.Header) bool {
	for _, value := range header.Values("Accept-Ranges") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "bytes") {
				return true
			}
		}
	}
	return false
}

func streamResumeInitialFullRange(value string) bool {
	parts := strings.SplitN(strings.TrimSpace(value), "=", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "bytes") {
		return false
	}
	return strings.TrimSpace(parts[1]) == "0-"
}

func streamResumeSingleByteRange(value string) bool {
	parts := strings.SplitN(strings.TrimSpace(value), "=", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "bytes") {
		return false
	}
	spec := strings.TrimSpace(parts[1])
	return spec != "" && strings.Contains(spec, "-") && !strings.Contains(spec, ",")
}

func streamResumeMultipart(header http.Header) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(header.Get("Content-Type"))), "multipart/byteranges")
}

func parseStreamContentRange(value string) (int64, int64, int64, bool) {
	m := contentRangeBytesRE.FindStringSubmatch(strings.TrimSpace(value))
	if len(m) != 4 || m[3] == "*" {
		return 0, 0, 0, false
	}
	start, errStart := strconv.ParseInt(m[1], 10, 64)
	end, errEnd := strconv.ParseInt(m[2], 10, 64)
	total, errTotal := strconv.ParseInt(m[3], 10, 64)
	if errStart != nil || errEnd != nil || errTotal != nil {
		return 0, 0, 0, false
	}
	return start, end, total, true
}

func responseContentLength(res *http.Response) int64 {
	if res == nil {
		return -1
	}
	if res.ContentLength > 0 {
		return res.ContentLength
	}
	value := strings.TrimSpace(res.Header.Get("Content-Length"))
	if value == "" {
		return res.ContentLength
	}
	length, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return res.ContentLength
	}
	return length
}

func streamResumeReadError(r *http.Request, err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		return false
	}
	if r != nil && r.Context().Err() != nil {
		return false
	}
	return true
}

func setStreamResumeAccessLogFields(ctx context.Context, progress streamResumeProgress) {
	if ctx == nil || (progress.attempts == 0 && progress.err == nil) {
		return
	}
	logResumeErr := progress.err != nil && (progress.attempts > 0 || progress.resumeErr)
	SetAccessLogField(ctx, "streamResumeAttempts", progress.attempts)
	if progress.resumedBytes > 0 {
		SetAccessLogField(ctx, "streamResumeBytes", progress.resumedBytes)
	}
	if progress.firstFrom >= 0 {
		SetAccessLogField(ctx, "streamResumeFrom", progress.firstFrom)
	}
	if logResumeErr {
		SetAccessLogField(ctx, "streamResumeError", progress.err.Error())
	}
}

func addStreamResumeLogFields(ctx context.Context, meta map[string]any) {
	if ctx == nil || meta == nil {
		return
	}
	fields := AccessLogFields(ctx)
	for _, key := range []string{"streamResumeAttempts", "streamResumeBytes", "streamResumeFrom", "streamResumeError"} {
		if value, ok := fields[key]; ok {
			meta[key] = value
		}
	}
}

func closeResponseBody(res *http.Response) {
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}
}

func drainAndCloseResponseBody(res *http.Response) {
	if res == nil || res.Body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, res.Body, streamResumeDrainLimit)
	_ = res.Body.Close()
}
