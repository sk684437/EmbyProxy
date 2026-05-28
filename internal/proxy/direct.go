package proxy

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

func (h *Handler) handleDirect(ctx context.Context, r *http.Request, rawPath string, env config.ProxyEnv, node storage.Node, body []byte) (*http.Response, error) {
	return h.handleDirectWithClient(ctx, r, rawPath, env, node, body, h.followClient)
}

func (h *Handler) handleRawDirect(ctx context.Context, r *http.Request, rawPath string, env config.ProxyEnv, node storage.Node, body []byte) (*http.Response, error) {
	client := h.rawClient
	if client == nil {
		client = newRawHTTPClient()
	}
	return h.handleDirectWithClient(ctx, r, rawPath, env, node, body, client)
}

func (h *Handler) handleDirectWithClient(ctx context.Context, r *http.Request, rawPath string, env config.ProxyEnv, node storage.Node, body []byte, client *http.Client) (*http.Response, error) {
	if client == nil {
		client = h.followClient
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
	candidates := h.makeDirectCandidates(rawPath, r.URL.RawQuery)
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
		applyIdentityToURL(h.ids, u, node)
		targetURL := u.String()
		headers := buildDirectOutboundHeaders(h.ids, r.Header, u, env, node, "normal")
		headers.Set("Accept-Encoding", "identity")
		currentHeaders := headers
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-normal", "targetUrl": targetURL, "outboundHeaders": headers})
		res, err := h.doFetch(ctx, client, u, method, headers, body)
		if err != nil {
			h.log.Warn("direct", "target failed", map[string]any{"id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "ms": time.Since(started).Milliseconds(), "error": err.Error()})
			lastErr = err
			continue
		}
		if rg := r.Header.Get("Range"); rg != "" {
			if rangeStartZero(rg) && ((res.StatusCode != http.StatusPartialContent && res.Header.Get("Content-Range") == "") || res.StatusCode == http.StatusRequestedRangeNotSatisfiable) {
				_ = res.Body.Close()
				hNoRange := cloneHeader(headers)
				hNoRange.Del("Range")
				hNoRange.Del("If-Range")
				hNoRange.Set("Accept-Encoding", "identity")
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
			h2 := buildDirectOutboundHeaders(h.ids, r.Header, u, env, node, "retry-no-origin")
			h2.Set("Accept-Encoding", "identity")
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
			h3 := buildDirectOutboundHeaders(h.ids, r.Header, u, env, node, "retry-browserish")
			h3.Set("Accept-Encoding", "identity")
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
				hNoRange.Set("Accept-Encoding", "identity")
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
							return h.handleDirectWithClient(ctx, r, abs.String(), env, node, body, client)
						}
						rh.Set("Location", abs.String())
					}
				}
			}
		}
		addCORSHeaders(rh, reqOrigin, env)
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-completed", "targetUrl": targetURL, "outboundHeaders": currentHeaders})
		targetMs := time.Since(started).Milliseconds()
		h.log.Info("direct", "target headers received", map[string]any{"id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "status": res.StatusCode, "ms": targetMs})
		SetAccessLogField(ctx, "targetMs", targetMs)
		res.Header = rh
		h.closeBody(lastRes)
		lastRes = nil
		return res, nil
	}
	if lastRes != nil {
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-last-retry-response", "targetUrl": rawPath})
		return lastRes, nil
	}
	if lastErr != nil {
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": directNodeName(nodeName), "stage": "direct-all-failed", "targetUrl": rawPath, "meta": map[string]any{"error": lastErr.Error()}})
		return nil, lastErr
	}
	return nil, errNoResponse
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
