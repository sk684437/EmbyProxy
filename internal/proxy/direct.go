package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

var errForbiddenDirectHost = errors.New("forbidden direct host")

func (h *Handler) handleDirect(ctx context.Context, r *http.Request, rawPath string, env config.ProxyEnv, node storage.Node, body []byte) (*http.Response, error) {
	return h.handleProtectedDirect(ctx, r, rawPath, env, node, body, false)
}

func (h *Handler) handleRawDirect(ctx context.Context, r *http.Request, rawPath string, env config.ProxyEnv, node storage.Node, body []byte) (*http.Response, error) {
	return h.handleProtectedDirect(ctx, r, rawPath, env, node, body, true)
}

func (h *Handler) handleProtectedDirect(ctx context.Context, r *http.Request, rawPath string, env config.ProxyEnv, node storage.Node, body []byte, inheritRequestQuery bool) (*http.Response, error) {
	return h.handleDirectWithClient(ctx, r, rawPath, env, node, body, h.protectedDirectClient(node, env), true, inheritRequestQuery)
}

func (h *Handler) protectedDirectClient(node storage.Node, env config.ProxyEnv) *http.Client {
	base := h.rawDirectClient
	if base == nil {
		base = newRawHTTPClient()
	}
	transport := base.Transport
	if transport == nil {
		transport = newProxyTransport(true)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   base.Timeout,
		Jar:       base.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !h.directURLAllowed(req.Context(), node, req.URL, env) {
				return errForbiddenDirectHost
			}
			return nil
		},
	}
}

func (h *Handler) directURLAllowed(ctx context.Context, node storage.Node, u *url.URL, env config.ProxyEnv) bool {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return h.rawHostAllowed(ctx, node, u, env)
}

func (h *Handler) handleDirectWithClient(ctx context.Context, r *http.Request, rawPath string, env config.ProxyEnv, node storage.Node, body []byte, client *http.Client, protectDirect bool, inheritRequestQuery bool) (*http.Response, error) {
	if client == nil {
		client = h.defaultFollowClient
	}
	if client == nil {
		client = newProxyHTTPClient(true)
	}
	method := strings.ToUpper(r.Method)
	reqOrigin := r.Header.Get("Origin")
	nodeName := strings.ToLower(strings.TrimSpace(node.Name))
	if nodeName == "" {
		nodeName = "-"
	}
	capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-start", "targetUrl": rawPath})
	rawQuery := ""
	if inheritRequestQuery && r.URL != nil {
		rawQuery = r.URL.RawQuery
	}
	candidates := h.makeDirectCandidates(rawPath, rawQuery)
	if body != nil && int64(len(body)) > h.cfg.Defaults.MaxRetryBodyBytes {
		candidates = candidates[:1]
	}
	requestID := requestID(r, h.log)
	var lastRes *http.Response
	var lastErr error
	for _, target := range candidates {
		started := time.Now()
		u, err := url.Parse(target)
		if err != nil {
			lastErr = err
			continue
		}
		outboundHeaders := cloneHeader(r.Header)
		applyIdentityToURL(h.ids, u, outboundHeaders, node)
		targetURL := u.String()
		if protectDirect && !h.directURLAllowed(ctx, node, u, env) {
			capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-forbidden", "targetUrl": targetURL, "outboundHeaders": http.Header{}})
			lastErr = errForbiddenDirectHost
			continue
		}
		headers := buildDirectOutboundHeaders(h.ids, outboundHeaders, u, env, node, "normal")
		currentHeaders := headers
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-normal", "targetUrl": targetURL, "outboundHeaders": headers})
		res, err := h.doFetch(ctx, client, u, method, headers, body)
		if err != nil {
			if errors.Is(err, errForbiddenDirectHost) {
				capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-forbidden-redirect", "targetUrl": targetURL})
				return localForbiddenResponse("direct", targetURL), nil
			}
			h.log.Warn("direct", "target failed", withAccessLogFields(ctx, map[string]any{"event": "targetFailed", "id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "targetAttemptMs": time.Since(started).Milliseconds(), "error": err.Error()}))
			lastErr = err
			continue
		}
		if rg := r.Header.Get("Range"); rg != "" {
			if rangeStartZero(rg) && ((res.StatusCode != http.StatusPartialContent && res.Header.Get("Content-Range") == "") || res.StatusCode == http.StatusRequestedRangeNotSatisfiable) {
				_ = res.Body.Close()
				hNoRange := cloneHeader(headers)
				hNoRange.Del("Range")
				hNoRange.Del("If-Range")
				currentHeaders = hNoRange
				capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-retry-no-range", "targetUrl": targetURL, "outboundHeaders": hNoRange})
				res, err = h.doFetch(ctx, client, u, method, hNoRange, body)
				if err != nil {
					lastErr = err
					continue
				}
			}
		}
		if res.StatusCode == http.StatusForbidden && int64(len(body)) <= h.cfg.Defaults.MaxRetryBodyBytes {
			_ = res.Body.Close()
			h2 := buildDirectOutboundHeaders(h.ids, outboundHeaders, u, env, node, "retry-no-origin")
			currentHeaders = h2
			capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-retry-no-origin", "targetUrl": targetURL, "outboundHeaders": h2})
			res, err = h.doFetch(ctx, client, u, method, h2, body)
			if err != nil {
				lastErr = err
				continue
			}
		}
		if res.StatusCode == http.StatusForbidden && int64(len(body)) <= h.cfg.Defaults.MaxRetryBodyBytes {
			_ = res.Body.Close()
			h3 := buildDirectOutboundHeaders(h.ids, outboundHeaders, u, env, node, "retry-browserish")
			currentHeaders = h3
			capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-retry-browserish", "targetUrl": targetURL, "outboundHeaders": h3})
			res, err = h.doFetch(ctx, client, u, method, h3, body)
			if err != nil {
				lastErr = err
				continue
			}
		}
		if rg := r.Header.Get("Range"); rg != "" && !isRetryableProtocolStatus(res.StatusCode) {
			if rangeStartZero(rg) && ((res.StatusCode != http.StatusPartialContent && res.Header.Get("Content-Range") == "") || res.StatusCode == http.StatusRequestedRangeNotSatisfiable) {
				_ = res.Body.Close()
				hNoRange := cloneHeader(currentHeaders)
				hNoRange.Del("Range")
				hNoRange.Del("If-Range")
				currentHeaders = hNoRange
				capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-retry-no-range-2", "targetUrl": targetURL, "outboundHeaders": hNoRange})
				res, err = h.doFetch(ctx, client, u, method, hNoRange, body)
				if err != nil {
					lastErr = err
					continue
				}
			}
		}
		if isRetryableProtocolStatus(res.StatusCode) {
			h.setLastResponse(&lastRes, res)
			continue
		}
		rh := cloneHeader(res.Header)
		reqPath := r.URL.RequestURI()
		rawIdx := strings.Index(reqPath, "/__raw__/")
		selfPrefixForRaw := ""
		if rawIdx >= 0 {
			selfPrefixForRaw = reqPath[:rawIdx]
		}
		rewriteSetCookieHeaders(rh, selfPrefixForRaw)
		fillContentLengthFromContentRange(rh)
		rh.Set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Range, Content-Length, Content-Type")
		if res.StatusCode == http.StatusPartialContent || res.Header.Get("Content-Range") != "" || acceptRangesBytesRE.MatchString(res.Header.Get("Accept-Ranges")) {
			rh.Set("Accept-Ranges", "bytes")
		} else {
			rh.Del("Accept-Ranges")
		}
		if res.StatusCode >= 300 && res.StatusCode < 400 && selfPrefixForRaw != "" {
			if loc := rh.Get("Location"); loc != "" {
				if abs, err := url.Parse(loc); err == nil {
					abs = res.Request.URL.ResolveReference(abs)
					if abs.Scheme == "http" || abs.Scheme == "https" {
						if !node.DirectExternal {
							_ = res.Body.Close()
							h.closeBody(lastRes)
							lastRes = nil
							capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-location-follow", "targetUrl": abs.String()})
							return h.handleDirectWithClient(ctx, r, abs.String(), env, node, body, client, protectDirect, inheritRequestQuery)
						}
						rh.Set("Location", abs.String())
					}
				}
			}
		}
		addCORSHeaders(rh, reqOrigin, env)
		rangeTarget := u
		if res.Request != nil && res.Request.URL != nil {
			rangeTarget = res.Request.URL
		}
		isStreaming := isDirectStreamingMedia(r, rangeTarget, rh, res.StatusCode)
		setStreamingRangeAccessLogFields(ctx, r, rangeTarget, rh, isStreaming)
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-completed", "targetUrl": targetURL, "outboundHeaders": currentHeaders})
		responseReadyMs := time.Since(started).Milliseconds()
		formattedTarget := logging.FormatTarget(targetURL)
		h.log.Info("direct", "response ready", withAccessLogFields(ctx, map[string]any{"event": "upstreamReady", "id": requestID, "node": nodeName, "target": formattedTarget, "status": res.StatusCode, "responseReadyMs": responseReadyMs}))
		SetAccessLogField(ctx, "responseReadyMs", responseReadyMs)
		MarkAccessLogResponseBodyStart(ctx, time.Now())
		res.Header = rh
		if isStreaming {
			markStreamResumeCandidate(res, "direct")
		}
		h.closeBody(lastRes)
		lastRes = nil
		return res, nil
	}
	if lastRes != nil {
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-last-retry-response", "targetUrl": rawPath})
		return lastRes, nil
	}
	if lastErr != nil {
		if errors.Is(lastErr, errForbiddenDirectHost) {
			capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-forbidden", "targetUrl": rawPath, "outboundHeaders": http.Header{}})
			return localForbiddenResponse("direct", rawPath), nil
		}
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-all-failed", "targetUrl": rawPath, "meta": map[string]any{"error": lastErr.Error()}})
		return nil, lastErr
	}
	return nil, errNoResponse
}

func localForbiddenResponse(kind, target string) *http.Response {
	body := "Forbidden " + kind + " host"
	res := textResponse(http.StatusForbidden, body, nil)
	res.Status = "403 " + body
	if u, err := url.Parse(target); err == nil {
		res.Request = &http.Request{URL: u}
	}
	return res
}

func isDirectStreamingMedia(r *http.Request, targetURL *url.URL, headers http.Header, status int) bool {
	if r != nil && r.URL != nil {
		path := strings.ToLower(r.URL.Path)
		if strings.Contains(path, "/sessions/playing") {
			return false
		}
		if isPlaybackPath(path) {
			return true
		}
	}
	if targetURL != nil {
		path := strings.ToLower(targetURL.Path)
		if strings.Contains(path, "/sessions/playing") {
			return false
		}
		if strings.Contains(path, "/videos/") || strings.Contains(path, "/audio/") || strings.Contains(path, "/hls/") || strings.Contains(path, "/dash/") {
			return true
		}
		if strings.Contains(path, "/items/") && (strings.Contains(path, "/download") || strings.Contains(path, "/stream") || strings.Contains(path, "/file")) {
			return true
		}
		if streamingRE.MatchString(path) || playbackMediaExtRE.MatchString(path) {
			return true
		}
	}
	return status == http.StatusPartialContent || strings.TrimSpace(headers.Get("Content-Range")) != ""
}

func rangeStartZero(value string) bool {
	m := rangeStartRE.FindStringSubmatch(value)
	if len(m) != 2 {
		return false
	}
	return m[1] == "0"
}

func directNodeName(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
