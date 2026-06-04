package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"embyproxy/internal/auth"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/storage"
)

const proxyRewriteBodyMaxBytes int64 = 10 * 1024 * 1024

var errProxyRewriteBodyTooLarge = errors.New("rewritable upstream response body is too large")

func (h *Handler) handleSTRM(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, finalURL *url.URL, body []byte, env config.ProxyEnv) (*http.Response, error) {
	headers := cloneHeader(r.Header)
	stripClientIPHeaders(headers)
	headers.Del("Range")
	headers.Del("If-Range")
	applyIdentity(h.ids, headers, node, true)
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-source", "targetUrl": finalURL.String(), "outboundHeaders": headers})
	res, err := h.fetchTarget(ctx, finalURL, http.MethodGet, headers, nil, true)
	if err != nil {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-source-failed", "targetUrl": finalURL.String(), "outboundHeaders": headers})
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return res, nil
	}
	defer res.Body.Close()
	raw, err := readProxyRewriteBody(res.Body)
	if err != nil {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-parse-error", "targetUrl": finalURL.String()})
		return textResponse(http.StatusBadGateway, "Bad Gateway", nil), nil
	}
	line := ""
	for _, item := range lineBreakRE.Split(strings.TrimSpace(string(raw)), -1) {
		item = strings.TrimSpace(item)
		if item != "" && !strings.HasPrefix(item, "#") {
			line = item
			break
		}
	}
	if !httpURLRE.MatchString(line) {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-bad-target", "targetUrl": finalURL.String()})
		return textResponse(http.StatusBadRequest, "Bad STRM", nil), nil
	}
	targetURL, err := url.Parse(line)
	if err != nil || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "strm-bad-protocol", "targetUrl": line})
		return textResponse(http.StatusBadRequest, "Bad STRM URL", nil), nil
	}
	capture.SetMeta(r, map[string]any{"mode": "direct", "node": parsed.Name, "secret": node.Secret, "stage": "strm-direct", "targetUrl": targetURL.String()})
	directRes, err := h.handleDirect(ctx, r, targetURL.String(), env, node, body)
	if err != nil {
		return nil, err
	}
	mode := "proxy"
	if directRes.StatusCode >= 300 && directRes.StatusCode < 400 {
		mode = "direct"
	}
	_ = h.store.LogPlayback(ctx, storage.PlaybackInput{Node: node, RequestIP: authClientIP(h, r), Headers: r.Header, Status: directRes.StatusCode, RespHeader: directRes.Header, IsPlayback: true, Mode: mode, RequestURL: r.URL.RequestURI(), Method: r.Method})
	return directRes, nil
}

func (h *Handler) tryAuthAPI(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, finalURL *url.URL, baseHeaders http.Header, body []byte, env config.ProxyEnv) *http.Response {
	rawAuthURL := cloneURL(finalURL)
	embyAuthURL := cloneURL(finalURL)
	if !embySlashPrefixRE.MatchString(embyAuthURL.Path) {
		embyAuthURL.Path = "/emby" + ensureLeadingSlash(embyAuthURL.Path)
	}
	urls := []*url.URL{embyAuthURL}
	if rawAuthURL.String() != embyAuthURL.String() {
		urls = append(urls, rawAuthURL)
	}
	reqBase := schemeHost(r)
	for _, u := range urls {
		for _, mode := range []string{"with-origin", "no-origin"} {
			hh := cloneHeader(baseHeaders)
			hh.Set("Accept", "application/json, text/plain, */*")
			hh.Set("Content-Type", "application/json;charset=utf-8")
			setProxyUA(h.ids, hh, node, r.Header.Get("User-Agent"))
			applyIdentity(h.ids, hh, node, true)
			if mode == "with-origin" {
				hh.Set("Origin", reqBase)
				hh.Set("Referer", reqBase+"/")
			} else {
				hh.Del("Origin")
				hh.Del("Referer")
			}
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "auth-" + mode, "targetUrl": u.String(), "outboundHeaders": hh})
			res, err := h.fetchTarget(ctx, u, r.Method, hh, body, false)
			if err != nil {
				continue
			}
			if isAuthSuccess(res) {
				return res
			}
			_ = res.Body.Close()
		}
	}
	_ = env
	return nil
}

func (h *Handler) handleMediaProxy(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, finalURL *url.URL, body []byte, env config.ProxyEnv, isPlaybackAPI, isImageAPI, isAdditionalPartsAPI bool, reqOrigin, clientIP string) (*http.Response, error) {
	isStreamingMedia := isPlaybackAPI || streamingRE.MatchString(finalURL.Path)
	hClean := buildCleanProxyHeaders(h.ids, r.Header, finalURL, node, env, isStreamingMedia)
	for _, key := range []string{"X-Emby-Authorization", "X-Emby-Token", "X-MediaBrowser-Token", "Authorization", "Cookie"} {
		if value := r.Header.Get(key); value != "" {
			hClean.Set(key, value)
		}
	}
	applyIdentity(h.ids, hClean, node, true)
	if finalURL.Query().Get("api_key") == "" {
		if apiKey := r.URL.Query().Get("api_key"); apiKey != "" {
			q := finalURL.Query()
			q.Set("api_key", apiKey)
			finalURL.RawQuery = q.Encode()
		}
	}
	stage := "media-proxy"
	if isImageAPI {
		stage = "image-proxy"
	} else if isAdditionalPartsAPI {
		stage = "additionalparts-proxy"
	}
	cacheKey := ""
	var imageCache *imageDiskCache
	var imageCacheFill *imageCacheFill
	finishImageCacheFill := func() {}
	if isImageAPI {
		imageCache = h.ensureImageCache(ctx)
		cacheKey = imageCacheKey(parsed.Name, finalURL)
		if imageCache == nil {
			SetAccessLogField(ctx, "imageCache", "disabled")
		} else if !imageCacheLookupMethod(r.Method) {
			SetAccessLogField(ctx, "imageCache", "bypass")
			SetAccessLogField(ctx, "imageCacheReason", "method")
		} else if r.Header.Get("Range") != "" {
			SetAccessLogField(ctx, "imageCache", "bypass")
			SetAccessLogField(ctx, "imageCacheReason", "range")
		} else if cached, ok := imageCache.get(r, cacheKey, reqOrigin, env); ok {
			SetAccessLogField(ctx, "imageCache", "hit")
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-cache-hit", "targetUrl": finalURL.String()})
			return cached, nil
		} else {
			fill, leader := imageCache.beginFill(cacheKey)
			if !leader {
				SetAccessLogField(ctx, "imageCache", "wait")
				if err := imageCache.waitFill(ctx, fill); err != nil {
					return nil, err
				}
				if cached, ok := imageCache.get(r, cacheKey, reqOrigin, env); ok {
					SetAccessLogField(ctx, "imageCache", "hit")
					SetAccessLogField(ctx, "imageCacheCoalesced", true)
					capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-cache-hit", "targetUrl": finalURL.String()})
					return cached, nil
				}
				SetAccessLogField(ctx, "imageCache", "miss")
				SetAccessLogField(ctx, "imageCacheCoalesced", true)
			} else {
				imageCacheFill = fill
				finishImageCacheFill = func() {
					imageCache.finishFill(imageCacheFill)
				}
				SetAccessLogField(ctx, "imageCache", "miss")
			}
		}
		release, err := h.acquireImageRequestSlot(ctx, parsed.Name)
		if err != nil {
			finishImageCacheFill()
			return nil, err
		}
		defer release()
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": stage, "targetUrl": finalURL.String(), "outboundHeaders": hClean})
	res, err := h.fetchTarget(ctx, finalURL, r.Method, hClean, body, true)
	if err != nil {
		finishImageCacheFill()
		return nil, err
	}
	if isImageAPI && res.StatusCode == http.StatusForbidden {
		_ = res.Body.Close()
		hImg := cloneHeader(hClean)
		stripClientIPHeaders(hImg)
		deleteHeaders(hImg, "Origin", "Referer", "Range", "If-Range")
		setProxyUA(h.ids, hImg, node, r.Header.Get("User-Agent"))
		hImg.Set("Accept", "image/avif,image/webp,image/apng,image*;q=0.8")
		hImg.Set("Accept-Encoding", "identity")
		applyIdentity(h.ids, hImg, node, true)
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-retry-clean", "targetUrl": finalURL.String(), "outboundHeaders": hImg})
		res, err = h.fetchTarget(ctx, finalURL, r.Method, hImg, nil, false)
		if err != nil {
			finishImageCacheFill()
			return nil, err
		}
		if res.StatusCode == http.StatusForbidden {
			_ = res.Body.Close()
			hImg2 := cloneHeader(hImg)
			hImg2.Set("Referer", originOf(finalURL)+"/")
			hImg2.Set("Origin", originOf(finalURL))
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "image-retry-origin", "targetUrl": finalURL.String(), "outboundHeaders": hImg2})
			res, err = h.fetchTarget(ctx, finalURL, r.Method, hImg2, nil, false)
			if err != nil {
				finishImageCacheFill()
				return nil, err
			}
		}
	}
	if isImageAPI && res.StatusCode == http.StatusTooManyRequests {
		h.noteImageRateLimited(parsed.Name, res.Header.Get("Retry-After"))
	}
	headers := cloneHeader(res.Header)
	addCORSHeaders(headers, reqOrigin, env)
	headers.Set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Range, Content-Length, Content-Type")
	if isStreamingMedia {
		if res.StatusCode == http.StatusPartialContent || res.Header.Get("Content-Range") != "" || acceptRangesBytesRE.MatchString(res.Header.Get("Accept-Ranges")) {
			headers.Set("Accept-Ranges", "bytes")
		} else {
			headers.Del("Accept-Ranges")
		}
		headers.Set("Cache-Control", "no-store, no-transform")
		if m3u8PathRE.MatchString(finalURL.Path) {
			headers.Set("Content-Type", "application/vnd.apple.mpegurl")
		}
	}
	if isImageAPI {
		headers.Del("Set-Cookie")
		headers.Del("Vary")
		setImageCacheControl(headers, res.StatusCode, "public, max-age=60, s-maxage=60")
		if imageCache != nil {
			if imageCache.wrapStore(r, cacheKey, res, headers, finishImageCacheFill) {
				finishImageCacheFill = func() {}
			}
		}
		finishImageCacheFill()
	}
	_ = h.store.LogPlayback(ctx, storage.PlaybackInput{Node: node, RequestIP: clientIP, Headers: r.Header, Status: res.StatusCode, RespHeader: headers, IsPlayback: isPlaybackAPI || isStreamingMedia, Mode: "proxy", RequestURL: r.URL.RequestURI(), Method: r.Method})
	res.Header = headers
	return res, nil
}

func (h *Handler) retryGeneral403(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, finalURL *url.URL, headers http.Header, body []byte, env config.ProxyEnv, ua string, base *url.URL) (*http.Response, http.Header, error) {
	h3 := cloneHeader(headers)
	stripClientIPHeaders(h3)
	h3.Set("Host", base.Host)
	setProxyUA(h.ids, h3, node, ua)
	if rg := r.Header.Get("Range"); rg != "" {
		h3.Set("Range", rg)
	}
	deleteHeaders(h3, "Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
	if isEmosNode(node, finalURL, env) {
		applyEmosHeaders(h3, env)
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "general-retry-clean", "targetUrl": finalURL.String(), "outboundHeaders": h3})
	res, err := h.fetchTarget(ctx, finalURL, r.Method, h3, body, false)
	if err != nil || res.StatusCode != http.StatusForbidden {
		return res, h3, err
	}
	for _, stage := range []string{"general-retry-origin", "general-retry-origin-repeat"} {
		_ = res.Body.Close()
		h4 := cloneHeader(h3)
		stripClientIPHeaders(h4)
		h4.Set("Host", base.Host)
		setProxyUA(h.ids, h4, node, ua)
		h4.Set("Referer", originOf(base)+"/")
		h4.Set("Origin", originOf(base))
		if rg := r.Header.Get("Range"); rg != "" {
			h4.Set("Range", rg)
		}
		deleteHeaders(h4, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
		if isEmosNode(node, finalURL, env) {
			applyEmosHeaders(h4, env)
		}
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": stage, "targetUrl": finalURL.String(), "outboundHeaders": h4})
		res, err = h.fetchTarget(ctx, finalURL, r.Method, h4, body, false)
		if err != nil || res.StatusCode != http.StatusForbidden {
			return res, h4, err
		}
		h3 = h4
	}
	return res, h3, nil
}

func (h *Handler) finishGeneralResponse(ctx context.Context, r *http.Request, res *http.Response, node storage.Node, parsed parsedRoute, finalURL *url.URL, base *url.URL, currentHeaders http.Header, env config.ProxyEnv, reqOrigin string, isStatic, isImageAPI, isStreaming bool) (*http.Response, error) {
	headers := cloneHeader(res.Header)
	addCORSHeaders(headers, reqOrigin, env)
	selfPrefix := routePrefix(parsed.Name, node.Secret)
	rewriteSetCookieHeaders(headers, selfPrefix)
	if isStatic {
		headers.Set("Access-Control-Allow-Origin", "*")
		headers.Del("Vary")
		headers.Del("Set-Cookie")
		headers.Set("Cache-Control", "public, max-age=31536000, s-maxage=86400")
	} else if isImageAPI {
		headers.Del("Set-Cookie")
		headers.Del("Vary")
		setImageCacheControl(headers, res.StatusCode, "public, max-age=2592000, s-maxage=2592000, immutable")
	} else if isStreaming {
		headers.Set("Cache-Control", "no-store, no-transform")
	}
	if loc := headers.Get("Location"); loc != "" {
		rewritten, direct, directURL := h.rewriteLocation(r, loc, node, parsed, base, selfPrefix)
		if direct {
			_ = res.Body.Close()
			capture.SetMeta(r, map[string]any{"mode": "direct", "node": parsed.Name, "secret": node.Secret, "stage": "location-direct", "targetUrl": directURL})
			if isTrustedSmartSTRMPath(parsed.Path) {
				trustedEnv := env
				trustedEnv.ExternalAllowAny = true
				return h.handleDirect(ctx, r, directURL, trustedEnv, node, nil)
			}
			return h.handleDirect(ctx, r, directURL, env, node, nil)
		}
		if rewritten != "" {
			headers.Set("Location", rewritten)
		}
	}
	ct := strings.ToLower(headers.Get("Content-Type"))
	if res.StatusCode >= 200 && res.StatusCode < 300 && (strings.Contains(ct, "application/vnd.apple.mpegurl") || strings.Contains(ct, "application/x-mpegurl") || strings.Contains(ct, "application/dash+xml")) {
		defer res.Body.Close()
		raw, err := readProxyRewriteBody(res.Body)
		if err != nil {
			return nil, err
		}
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "manifest-rewrite", "targetUrl": finalURL.String(), "outboundHeaders": currentHeaders})
		rewritten := h.rewriteBodyLinks(ctx, string(raw), schemeHost(r)+r.URL.RequestURI(), node, parsed.Name, node.Secret)
		headers.Del("Content-Length")
		return bytesResponse(res.StatusCode, []byte(rewritten), headers), nil
	}
	if res.StatusCode >= 200 && res.StatusCode < 300 && strings.Contains(ct, "application/json") && strings.Contains(strings.ToLower(r.URL.RequestURI()), "/playbackinfo") {
		defer res.Body.Close()
		raw, err := readProxyRewriteBody(res.Body)
		if err != nil {
			return nil, err
		}
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "playbackinfo-rewrite", "targetUrl": finalURL.String(), "outboundHeaders": currentHeaders})
		rewritten := h.rewriteBodyLinks(ctx, string(raw), schemeHost(r)+r.URL.RequestURI(), node, parsed.Name, node.Secret)
		headers.Del("Content-Length")
		return bytesResponse(res.StatusCode, []byte(rewritten), headers), nil
	}
	if res.StatusCode >= 200 && res.StatusCode < 300 && strings.Contains(ct, "application/json") && isSystemInfoPath(parsed.Path) {
		defer res.Body.Close()
		raw, err := readProxyRewriteBody(res.Body)
		if err != nil {
			return nil, err
		}
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "systeminfo-rewrite", "targetUrl": finalURL.String(), "outboundHeaders": currentHeaders})
		rewritten, changed := rewriteSystemInfoAddresses(raw, schemeHost(r)+selfPrefix)
		if changed {
			headers.Del("Content-Length")
		}
		return bytesResponse(res.StatusCode, rewritten, headers), nil
	}
	res.Header = headers
	return res, nil
}

func readProxyRewriteBody(body io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, proxyRewriteBodyMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > proxyRewriteBodyMaxBytes {
		return nil, errProxyRewriteBodyTooLarge
	}
	return raw, nil
}

func (h *Handler) rewriteLocation(r *http.Request, location string, node storage.Node, parsed parsedRoute, base *url.URL, selfPrefix string) (string, bool, string) {
	origin := schemeHost(r)
	selfPrefixNoSlash := strings.TrimRight(selfPrefix, "/")
	if strings.HasPrefix(location, "/") {
		if location == selfPrefixNoSlash || strings.HasPrefix(location, selfPrefixNoSlash+"/") {
			return "", false, ""
		}
		return origin + selfPrefix + location, false, ""
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", false, ""
	}
	locHost := strings.ToLower(loc.Host)
	baseHost := strings.ToLower(base.Host)
	alreadyPrefixed := loc.Path == selfPrefixNoSlash || strings.HasPrefix(loc.Path, selfPrefixNoSlash+"/")
	if alreadyPrefixed {
		return "", false, ""
	}
	if locHost == baseHost {
		return origin + selfPrefix + loc.Path + queryAndHash(loc), false, ""
	}
	if !node.DirectExternal {
		return "", true, loc.String()
	}
	return loc.String(), false, ""
}

func isTrustedSmartSTRMPath(path string) bool {
	path = strings.ToLower(strings.TrimRight(strings.TrimSpace(path), "/"))
	return path == "/smartstrm" || path == "/emby/smartstrm"
}

func (h *Handler) rewriteBodyLinks(ctx context.Context, text, requestURL string, currentNode storage.Node, currentName, currentKey string) string {
	if text == "" {
		return text
	}
	reqURL, err := url.Parse(requestURL)
	if err != nil {
		return text
	}
	origin := reqURL.Scheme + "://" + reqURL.Host
	selfPrefix := routePrefix(currentName, currentKey)
	if currentNode.DirectExternal {
		return text
	}
	curHosts := map[string]bool{}
	for _, target := range storage.SplitTargets(currentNode.Target) {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			curHosts[strings.ToLower(u.Host)] = true
		}
	}
	hostMap, _ := h.store.GetHostIndex(ctx, "admin")
	matches := uniqueStrings(bodyURLRE.FindAllString(text, -1))
	if len(matches) == 0 {
		return text
	}
	replacements := map[string]string{}
	for _, full := range matches {
		u, err := url.Parse(full)
		if err != nil {
			continue
		}
		if u.Scheme+"://"+u.Host == origin && (u.Path == selfPrefix || strings.HasPrefix(u.Path, selfPrefix+"/")) {
			continue
		}
		host := strings.ToLower(u.Host)
		if curHosts[host] {
			replacements[full] = origin + selfPrefix + u.Path + queryAndHash(u)
			continue
		}
		if match, ok := hostMap[host]; ok {
			replacements[full] = origin + routePrefix(match.Name, match.Secret) + u.Path + queryAndHash(u)
			continue
		}
		replacements[full] = origin + selfPrefix + "/__raw__/" + url.QueryEscape(full)
	}
	out := text
	for from, to := range replacements {
		out = strings.ReplaceAll(out, from, to)
	}
	return out
}

func isSystemInfoPath(path string) bool {
	p := strings.ToLower(strings.Trim(path, "/"))
	return p == "system/info" || p == "system/info/public" || p == "emby/system/info" || p == "emby/system/info/public"
}

func rewriteSystemInfoAddresses(raw []byte, publicBase string) ([]byte, bool) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw, false
	}
	changed := false
	for key, value := range payload {
		if !isSystemInfoAddressKey(key) {
			continue
		}
		switch value.(type) {
		case string:
			payload[key] = publicBase
			changed = true
		case []any:
			payload[key] = []any{publicBase}
			changed = true
		}
	}
	if !changed {
		return raw, false
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return raw, false
	}
	return out, true
}

func isSystemInfoAddressKey(key string) bool {
	switch strings.ToLower(key) {
	case "localaddress", "wanaddress", "remoteaddress", "publicaddress", "publicurl", "localaddresses", "wanaddresses", "remoteaddresses":
		return true
	default:
		return false
	}
}

func setImageCacheControl(headers http.Header, status int, cacheValue string) {
	if status == http.StatusNotModified || (status >= 200 && status < 300) {
		headers.Set("Cache-Control", cacheValue)
		return
	}
	headers.Set("Cache-Control", "no-store")
}

func isAuthSuccess(res *http.Response) bool {
	if res.StatusCode == http.StatusMovedPermanently || res.StatusCode == http.StatusFound || res.StatusCode == http.StatusSeeOther || res.StatusCode == http.StatusTemporaryRedirect || res.StatusCode == http.StatusPermanentRedirect {
		return false
	}
	if !strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "application/json") {
		return false
	}
	return res.StatusCode == http.StatusOK || res.StatusCode == http.StatusUnauthorized
}

func cloneURL(u *url.URL) *url.URL {
	v := *u
	return &v
}

func originOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func authClientIP(h *Handler, r *http.Request) string {
	return auth.ClientIP(r, h.trustsProxy(r.Context()))
}

func queryAndHash(u *url.URL) string {
	out := ""
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
