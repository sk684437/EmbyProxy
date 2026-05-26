package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"embyproxy/internal/auth"
	"embyproxy/internal/capture"
	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
)

type Handler struct {
	cfg              config.Config
	store            *storage.Store
	ids              *identity.Manager
	log              *logging.Logger
	lineBan          *ttlMap
	progressThrottle *ttlMap
	playbackDedup    *ttlMap
	activeMu         sync.Mutex
	activeTarget     map[string]string
	manualClient     *http.Client
	followClient     *http.Client
}

type parsedRoute struct {
	URL      *url.URL
	Segments []string
	Name     string
	Secret   string
	Path     string
	HasKey   bool
}

func New(cfg config.Config, store *storage.Store, ids *identity.Manager, log *logging.Logger) *Handler {
	return &Handler{
		cfg:              cfg,
		store:            store,
		ids:              ids,
		log:              log,
		lineBan:          newTTLMap(),
		progressThrottle: newTTLMap(),
		playbackDedup:    newTTLMap(),
		activeTarget:     map[string]string{},
		manualClient: &http.Client{Timeout: 0, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		followClient: &http.Client{Timeout: 0},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	capture.SetMeta(r, map[string]any{"mode": "proxy", "stage": "route-parse"})
	parsed, status, message := h.parseRequest(r)
	if status != 0 {
		capture.SetMeta(r, map[string]any{"stage": routeStage(status, message)})
		http.Error(w, message, status)
		return
	}
	capture.SetMeta(r, map[string]any{"node": parsed.Name, "stage": "node-lookup"})
	node, err := h.store.GetNode(ctx, "admin", parsed.Name)
	if err != nil {
		h.log.Error("proxy", "node lookup failed", map[string]any{"node": parsed.Name, "error": err.Error()})
		http.Error(w, "Node lookup failed", http.StatusInternalServerError)
		return
	}
	if node == nil {
		capture.SetMeta(r, map[string]any{"node": parsed.Name, "stage": "node-not-found"})
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}
	parsed.Secret = node.Secret
	strip := 1
	if node.Secret != "" {
		if len(parsed.Segments) < 2 || parsed.Segments[1] != node.Secret {
			capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "invalid-secret"})
			h.log.Warn("proxy", "invalid node secret", map[string]any{"node": parsed.Name, "ip": auth.ClientIP(r, h.trustsProxy(ctx))})
			http.Error(w, "Node not found", http.StatusNotFound)
			return
		}
		strip = 2
		parsed.HasKey = true
	}
	parsed.Path = buildRemainingPath(parsed.URL, parsed.Segments, strip)
	capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "route-ready"})
	if parsed.Path == "/" && !strings.HasSuffix(r.URL.Path, "/") {
		capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "trailing-slash-redirect"})
		redirect := *r.URL
		redirect.Path += "/"
		http.Redirect(w, r, redirect.String(), http.StatusMovedPermanently)
		return
	}
	env := h.proxyEnv(ctx)
	if r.Method == http.MethodOptions {
		capture.SetMeta(r, map[string]any{"node": parsed.Name, "secret": node.Secret, "stage": "cors-preflight"})
		sendCORSPreflight(w, r.Header.Get("Origin"), env)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		h.handleWebSocket(w, r, *node, parsed)
		return
	}
	body, err := h.requestBodyForReplay(w, r)
	if err != nil {
		http.Error(w, "Request body error", http.StatusBadRequest)
		return
	}
	res, err := h.handleNode(ctx, r, *node, parsed, body, env)
	if err != nil {
		h.log.Error("proxy", "request failed", map[string]any{"node": parsed.Name, "error": err.Error()})
		http.Error(w, "Proxy Error: "+err.Error(), http.StatusBadGateway)
		return
	}
	h.sendResponse(w, res)
}

func (h *Handler) CleanupTTLMaps() {
	h.lineBan.Cleanup()
	h.progressThrottle.Cleanup()
	h.playbackDedup.Cleanup()
}

func (h *Handler) ResetNodeRoutingState(uid, name string) {
	key := strings.TrimSpace(uid + ":" + strings.ToLower(name))
	if key == ":" {
		return
	}
	h.activeMu.Lock()
	delete(h.activeTarget, key)
	h.activeMu.Unlock()
	h.lineBan.DeletePrefix(key + "|")
}

func (h *Handler) parseRequest(r *http.Request) (parsedRoute, int, string) {
	segments := []string{}
	trimmed := strings.Trim(r.URL.Path, "/")
	if trimmed != "" {
		for _, part := range strings.Split(trimmed, "/") {
			decoded, err := url.PathUnescape(part)
			if err != nil {
				return parsedRoute{}, http.StatusBadRequest, "Bad Request: invalid URL encoding"
			}
			segments = append(segments, decoded)
		}
	}
	name := strings.ToLower(strings.TrimSpace(firstSegment(segments)))
	if name == "" {
		return parsedRoute{}, http.StatusBadRequest, "Missing node name"
	}
	if !nodeNameRE.MatchString(name) {
		return parsedRoute{}, http.StatusNotFound, "Node not found"
	}
	return parsedRoute{URL: r.URL, Segments: segments, Name: name}, 0, ""
}

func (h *Handler) handleNode(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, body []byte, env config.ProxyEnv) (*http.Response, error) {
	targets := storage.SplitTargets(node.Target)
	requestID := requestID(r, h.log)
	nodeName := parsed.Name
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": nodeName, "secret": node.Secret, "stage": "proxy-handle"})
	if len(targets) == 0 {
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": nodeName, "secret": node.Secret, "stage": "no-targets"})
		return textResponse(http.StatusInternalServerError, "Invalid node target", nil), nil
	}
	nodeKey := "admin:" + nodeName
	expectedActive, ordered := h.targetOrder(nodeKey, targets)
	var lastRes *http.Response
	var lastErr error
	tried := 0
	for _, target := range ordered {
		banKey := nodeKey + "|" + target
		if _, banned := h.lineBan.Get(banKey); banned && len(targets) > 1 {
			continue
		}
		tried++
		started := time.Now()
		nodeTry := node
		nodeTry.Target = target
		res, err := h.handleOneTarget(ctx, r, nodeTry, parsed, body, env)
		if err != nil {
			h.lineBan.Set(banKey, 1, time.Minute)
			h.log.Warn("proxy", "target failed", map[string]any{"id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "ms": time.Since(started).Milliseconds(), "error": err.Error()})
			lastErr = err
			h.setLastResponse(&lastRes, textResponse(http.StatusBadGateway, "Proxy Error: "+err.Error(), nil))
			continue
		}
		status := res.StatusCode
		if status < 500 && status != http.StatusForbidden && status != http.StatusNotFound && status != http.StatusRequestedRangeNotSatisfiable {
			h.closeBody(lastRes)
			lastRes = nil
			h.markTargetHealthy(nodeKey, targets, target, expectedActive)
			h.log.Info("proxy", "target completed", map[string]any{"id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "status": status, "ms": time.Since(started).Milliseconds()})
			return res, nil
		}
		h.lineBan.Set(banKey, 1, time.Minute)
		h.log.Warn("proxy", "target returned retryable status", map[string]any{"id": requestID, "node": nodeName, "target": logging.FormatTarget(target), "status": status, "ms": time.Since(started).Milliseconds()})
		h.setLastResponse(&lastRes, res)
	}
	if tried == 0 {
		for _, target := range ordered {
			nodeTry := node
			nodeTry.Target = target
			res, err := h.handleOneTarget(ctx, r, nodeTry, parsed, body, env)
			if err != nil {
				lastErr = err
				h.setLastResponse(&lastRes, textResponse(http.StatusBadGateway, "Proxy Error: "+err.Error(), nil))
				continue
			}
			status := res.StatusCode
			if status < 500 && status != http.StatusForbidden && status != http.StatusNotFound && status != http.StatusRequestedRangeNotSatisfiable {
				h.closeBody(lastRes)
				lastRes = nil
				h.markTargetHealthy(nodeKey, targets, target, expectedActive)
				return res, nil
			}
			h.setLastResponse(&lastRes, res)
		}
	}
	if lastRes != nil {
		return lastRes, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return textResponse(http.StatusBadGateway, "Proxy Error: all targets failed", nil), nil
}

func (h *Handler) handleOneTarget(ctx context.Context, r *http.Request, node storage.Node, parsed parsedRoute, body []byte, env config.ProxyEnv) (*http.Response, error) {
	base, err := url.Parse(node.Target)
	if err != nil {
		return nil, err
	}
	ua := r.Header.Get("User-Agent")
	isCapy := isCapyClient(r)
	clientIP := auth.ClientIP(r, h.trustsProxy(ctx))
	reqOrigin := r.Header.Get("Origin")
	forwardPath := parsed.Path
	basePath := strings.TrimRight(base.Path, "/")
	if embyPathRE.MatchString(forwardPath) && embyPathRE.MatchString(basePath) {
		forwardPath = embyPrefixRE.ReplaceAllString(forwardPath, "")
		if forwardPath == "" {
			forwardPath = "/"
		}
	}
	if env.CapyStripEmby == "1" && isCapy && embyPathRE.MatchString(forwardPath) {
		forwardPath = embyPrefixRE.ReplaceAllString(forwardPath, "")
		if forwardPath == "" {
			forwardPath = "/"
		}
	}
	if node.StreamTarget == "" && strings.HasPrefix(forwardPath, "/__raw__/") {
		raw := strings.TrimPrefix(forwardPath, "/__raw__/")
		if decoded, err := url.PathUnescape(raw); err == nil {
			raw = decoded
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "raw-bad-url"})
			return textResponse(http.StatusBadRequest, "Bad raw url", nil), nil
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "raw-bad-protocol"})
			return textResponse(http.StatusBadRequest, "Bad Request", nil), nil
		}
		if !h.rawHostAllowed(node, u, env) {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "raw-forbidden", "targetUrl": u.String()})
			return textResponse(http.StatusForbidden, "Forbidden raw host", nil), nil
		}
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": parsed.Name, "secret": node.Secret, "stage": "raw-direct", "targetUrl": u.String()})
		return h.handleDirect(ctx, r, raw, env, node, body)
	}
	finalURL := resolveTargetURL(base, forwardPath, r.URL.RawQuery)
	applyIdentityToURL(h.ids, finalURL, node)
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "proxy-target", "targetUrl": finalURL.String()})
	if h.isSTRM(finalURL.Path) && !strmStreamPathRE.MatchString(finalURL.Path) {
		return h.handleSTRM(ctx, r, node, parsed, finalURL, body, env)
	}
	p := strings.ToLower(finalURL.Path)
	isStreaming := streamingRE.MatchString(forwardPath)
	isStatic := (staticExtRE.MatchString(forwardPath) || embyImagesRE.MatchString(forwardPath)) && r.Method == http.MethodGet
	isAuthAPI := authAPIRE.MatchString(p)
	isPlaybackAPI := isPlaybackPath(p)
	isImageAPI := isImagePath(finalURL.Path)
	isAdditionalPartsAPI := isAdditionalPartsPath(finalURL.Path)
	needCompatOrigin := isAuthAPI || isPlaybackAPI
	headers := cloneHeader(r.Header)
	stripClientIPHeaders(headers)
	if isCapy && isAuthAPI {
		deleteHeaders(headers, "X-Emby-Token", "X-MediaBrowser-Token", "X-Authorization")
		az := headers.Get("Authorization")
		if bearerOrTokenRE.MatchString(az) {
			headers.Del("Authorization")
		}
		if headers.Get("Content-Type") == "" {
			headers.Set("Content-Type", "application/json;charset=utf-8")
		}
	}
	headers.Set("Host", base.Host)
	authz := headers.Get("Authorization")
	xEmby := headers.Get("X-Emby-Authorization")
	if !isAuthAPI && mediaBrowserAuthRE.MatchString(authz) && xEmby == "" {
		headers.Set("X-Emby-Authorization", authz)
	}
	if !isAuthAPI && authz == "" && xEmby != "" {
		headers.Set("Authorization", xEmby)
	}
	applyIdentity(h.ids, headers, node, true)
	if needCompatOrigin {
		if isPlaybackAPI {
			deleteHeaders(headers, "Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
			headers.Set("Accept", "*/*")
		} else {
			reqBase := schemeHost(r)
			if headers.Get("Origin") == "" {
				headers.Set("Origin", reqBase)
			}
			if headers.Get("Referer") == "" {
				headers.Set("Referer", reqBase+"/")
			}
			if headers.Get("Accept") == "" {
				headers.Set("Accept", "application/json, text/plain, */*")
			}
			if isAuthAPI && headers.Get("X-Requested-With") == "" {
				headers.Set("X-Requested-With", "XMLHttpRequest")
			}
		}
	}
	setProxyUA(h.ids, headers, node, ua)
	headers.Set("Accept-Encoding", "identity")
	if isPlaybackAPI {
		deleteHeaders(headers, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Priority")
	}
	if isStatic {
		headers.Del("Range")
	}
	if isEmosNode(node, finalURL, env) {
		applyEmosHeaders(headers, env)
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "proxy-prepared", "targetUrl": finalURL.String(), "outboundHeaders": headers})
	currentHeaders := headers
	if strings.HasPrefix(p, "/emby/sessions/playing/progress") && r.Method != http.MethodOptions {
		deviceID := r.Header.Get("X-Emby-Device-Id")
		sessionID := finalURL.Query().Get("SessionId")
		if sessionID == "" {
			sessionID = finalURL.Query().Get("sessionId")
		}
		key := clientIP + "|" + deviceID + "|" + sessionID
		if _, ok := h.progressThrottle.Get(key); ok {
			capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "progress-throttle", "targetUrl": finalURL.String(), "outboundHeaders": headers})
			return textResponse(http.StatusNoContent, "", http.Header{"Cache-Control": []string{"no-store"}}), nil
		}
		h.progressThrottle.Set(key, 1, time.Duration(h.cfg.Defaults.ProgressThrottleMS)*time.Millisecond)
	}
	if isAuthAPI && r.Method == http.MethodPost {
		if res := h.tryAuthAPI(ctx, r, node, parsed, finalURL, headers, body, env); res != nil {
			return res, nil
		}
	}
	nodeDirect := node.DirectExternal
	isGetLike := r.Method == http.MethodGet || r.Method == http.MethodHead
	if nodeDirect && isPlaybackAPI && !isAdditionalPartsAPI && isGetLike {
		capture.SetMeta(r, map[string]any{"mode": "direct", "node": parsed.Name, "secret": node.Secret, "stage": "playback-direct-302", "targetUrl": finalURL.String(), "outboundHeaders": headers})
		res := textResponse(http.StatusFound, "", http.Header{"Location": []string{finalURL.String()}, "Cache-Control": []string{"no-store"}, "X-FD-Stage": []string{"playback-direct-302"}})
		_ = h.store.LogPlayback(ctx, storage.PlaybackInput{Node: node, RequestIP: clientIP, Headers: r.Header, Status: res.StatusCode, RespHeader: res.Header, IsPlayback: true, Mode: "direct", RequestURL: r.URL.RequestURI(), Method: r.Method})
		return res, nil
	}
	shouldProxyMedia := (!nodeDirect && (isPlaybackAPI || isImageAPI || isAdditionalPartsAPI)) || (nodeDirect && (isAdditionalPartsAPI || isImageAPI))
	if shouldProxyMedia {
		return h.handleMediaProxy(ctx, r, node, parsed, finalURL, body, env, isPlaybackAPI, isImageAPI, isAdditionalPartsAPI, reqOrigin, clientIP)
	}
	capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "general-proxy", "targetUrl": finalURL.String(), "outboundHeaders": headers})
	res, err := h.fetchWithProtocolFallback(ctx, finalURL, r.Method, headers, body, false)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusForbidden && needCompatOrigin {
		h2 := cloneHeader(headers)
		if isEmosNode(node, finalURL, env) {
			applyEmosHeaders(h2, env)
		}
		reqBase := schemeHost(r)
		h2.Set("Origin", reqBase)
		h2.Set("Referer", reqBase+"/")
		currentHeaders = h2
		capture.SetMeta(r, map[string]any{"mode": "proxy", "node": parsed.Name, "secret": node.Secret, "stage": "general-retry-compat-origin", "targetUrl": finalURL.String(), "outboundHeaders": h2})
		res, err = h.fetchWithProtocolFallback(ctx, finalURL, r.Method, h2, body, false)
		if err != nil {
			return nil, err
		}
	}
	if res.StatusCode == http.StatusForbidden {
		res, currentHeaders, err = h.retryGeneral403(ctx, r, node, parsed, finalURL, headers, body, env, ua, base)
		if err != nil {
			return nil, err
		}
	}
	return h.finishGeneralResponse(ctx, r, res, node, parsed, finalURL, base, currentHeaders, env, reqOrigin, isStatic, isImageAPI, isStreaming)
}

func (h *Handler) requestBodyForReplay(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Body == nil {
		return nil, nil
	}
	return capture.DrainAndRemember(r, h.cfg.Defaults.MaxRetryBodyBytes)
}

func (h *Handler) sendResponse(w http.ResponseWriter, res *http.Response) {
	if res == nil {
		http.Error(w, "No response", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	copyResponseHeaders(w.Header(), res.Header)
	w.WriteHeader(res.StatusCode)
	if res.Body != nil {
		_, _ = io.Copy(w, res.Body)
	}
}

func (h *Handler) fetchWithProtocolFallback(ctx context.Context, target *url.URL, method string, headers http.Header, body []byte, follow bool) (*http.Response, error) {
	client := h.manualClient
	if follow {
		client = h.followClient
	}
	first, err := h.doFetch(ctx, client, target, method, headers, body)
	if err == nil && first.StatusCode != 525 && first.StatusCode != 526 && first.StatusCode != 530 {
		return first, nil
	}
	if body != nil && int64(len(body)) > h.cfg.Defaults.MaxRetryBodyBytes {
		if err == nil {
			return first, nil
		}
		h.closeBody(first)
		return nil, err
	}
	alt := *target
	if alt.Scheme == "https" {
		alt.Scheme = "http"
	} else {
		alt.Scheme = "https"
	}
	second, err2 := h.doFetch(ctx, client, &alt, method, headers, body)
	if err2 != nil {
		if err != nil {
			h.closeBody(first)
			return nil, err2
		}
		return first, nil
	}
	h.closeBody(first)
	return second, nil
}

func (h *Handler) doFetch(ctx context.Context, client *http.Client, target *url.URL, method string, headers http.Header, body []byte) (*http.Response, error) {
	var reader io.Reader
	if method != http.MethodGet && method != http.MethodHead && body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header = cloneHeader(headers)
	req.Host = target.Host
	return client.Do(req)
}

func textResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func bytesResponse(status int, body []byte, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: headers, Body: io.NopCloser(bytes.NewReader(body))}
}

func buildRemainingPath(u *url.URL, segments []string, strip int) string {
	path := "/"
	if len(segments) > strip {
		path += strings.Join(segments[strip:], "/")
	}
	if strings.HasSuffix(u.Path, "/") && path != "/" {
		path += "/"
	}
	return path
}

func resolveTargetURL(base *url.URL, path, rawQuery string) *url.URL {
	u := *base
	basePath := strings.TrimRight(base.Path, "/")
	if basePath == "" {
		u.Path = path
	} else {
		u.Path = basePath + ensureLeadingSlash(path)
	}
	if rawQuery != "" {
		q := u.Query()
		incoming, _ := url.ParseQuery(rawQuery)
		for key, values := range incoming {
			for _, value := range values {
				q.Set(key, value)
			}
		}
		u.RawQuery = q.Encode()
	}
	return &u
}

func ensureLeadingSlash(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return "/" + path
}

func firstSegment(segments []string) string {
	if len(segments) == 0 {
		return ""
	}
	return segments[0]
}

func routeStage(status int, message string) string {
	if status == http.StatusBadRequest && strings.Contains(message, "encoding") {
		return "bad-encoding"
	}
	if status == http.StatusBadRequest {
		return "missing-name"
	}
	return "invalid-name"
}

func schemeHost(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return scheme + "://" + r.Host
}

func requestID(r *http.Request, log *logging.Logger) string {
	if id := r.Context().Value("requestID"); id != nil {
		if s, ok := id.(string); ok && s != "" {
			return s
		}
	}
	return log.NextRequestID("")
}

func (h *Handler) proxyEnv(ctx context.Context) config.ProxyEnv {
	env := h.cfg.ProxyEnv()
	cfg, err := h.store.GetSystemConfig(ctx, h.defaultSystemConfig())
	if err != nil {
		h.log.Warn("proxy", "system config lookup failed", map[string]any{"error": err.Error()})
		return env
	}
	env.CapyStripEmby = cfg.CapyStripEmby
	env.EmosCompat = cfg.EmosCompat
	env.EmosMatchHosts = cfg.EmosMatchHosts
	env.EmosProxyID = cfg.EmosProxyID
	env.EmosProxyName = cfg.EmosProxyName
	env.CORSAllowOrigin = cfg.CORSAllowOrigin
	env.ExternalAllowHosts = cfg.ExternalAllowHosts
	env.ExternalAllowAny = cfg.ExternalAllowAny
	return env
}

func (h *Handler) trustsProxy(ctx context.Context) bool {
	defaults := h.defaultSystemConfig()
	cfg, err := h.store.GetSystemConfig(ctx, defaults)
	if err != nil {
		h.log.Warn("proxy", "system config lookup failed", map[string]any{"error": err.Error()})
		return defaults.TrustProxy
	}
	return cfg.TrustProxy
}

func (h *Handler) defaultSystemConfig() storage.SystemConfig {
	return storage.DefaultSystemConfig()
}

func (h *Handler) rawHostAllowed(node storage.Node, rawURL *url.URL, env config.ProxyEnv) bool {
	if env.ExternalAllowAny {
		return true
	}
	allowed := map[string]bool{}
	for _, target := range storage.SplitTargets(node.Target) {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			allowed[strings.ToLower(u.Host)] = true
		}
	}
	for _, item := range strings.Split(env.ExternalAllowHosts, ",") {
		if host := strings.TrimSpace(strings.ToLower(item)); host != "" {
			allowed[host] = true
		}
	}
	return allowed[strings.ToLower(rawURL.Host)]
}

func (h *Handler) isSTRM(path string) bool {
	return strmExtRE.MatchString(path)
}

func (h *Handler) getActiveTarget(nodeKey string, targets []string) string {
	h.activeMu.Lock()
	defer h.activeMu.Unlock()
	active := h.activeTarget[nodeKey]
	if active != "" && contains(targets, active) {
		return active
	}
	first := ""
	if len(targets) > 0 {
		first = targets[0]
		h.activeTarget[nodeKey] = first
	}
	return first
}

func (h *Handler) targetOrder(nodeKey string, targets []string) (string, []string) {
	active := h.getActiveTarget(nodeKey, targets)
	idx := indexOf(targets, active)
	if idx < 0 {
		return active, append([]string(nil), targets...)
	}
	out := append([]string{}, targets[idx:]...)
	out = append(out, targets[:idx]...)
	return active, out
}

func (h *Handler) markTargetHealthy(nodeKey string, targets []string, target, expectedActive string) bool {
	h.activeMu.Lock()
	defer h.activeMu.Unlock()
	current := h.activeTarget[nodeKey]
	if current == "" && len(targets) > 0 {
		current = targets[0]
	}
	if expectedActive != "" && current != expectedActive && current != target {
		return false
	}
	if contains(targets, target) {
		h.activeTarget[nodeKey] = target
		return true
	}
	return false
}

func contains(values []string, value string) bool {
	return indexOf(values, value) >= 0
}

func indexOf(values []string, value string) int {
	for i, item := range values {
		if item == value {
			return i
		}
	}
	return -1
}

func (h *Handler) makeDirectCandidates(rawPath, rawQuery string) []string {
	withQuery := func(value string) string {
		if rawQuery == "" {
			return value
		}
		sep := "?"
		if strings.Contains(value, "?") {
			sep = "&"
		}
		return value + sep + rawQuery
	}
	p := strings.TrimSpace(rawPath)
	if httpURLRE.MatchString(p) {
		return []string{withQuery(p)}
	}
	hostPart := strings.Split(strings.Split(strings.Split(p, "/")[0], "?")[0], "#")[0]
	if defaultPort80RE.MatchString(hostPart) {
		return []string{withQuery("http://" + p), withQuery("https://" + p)}
	}
	if defaultPort443RE.MatchString(hostPart) {
		return []string{withQuery("https://" + p), withQuery("http://" + p)}
	}
	return []string{withQuery("https://" + p), withQuery("http://" + p)}
}

func (h *Handler) closeBody(res *http.Response) {
	if res != nil && res.Body != nil {
		_ = res.Body.Close()
	}
}

func (h *Handler) setLastResponse(slot **http.Response, res *http.Response) {
	if slot == nil {
		return
	}
	if *slot != nil && *slot != res {
		h.closeBody(*slot)
	}
	*slot = res
}

func isRetryableProtocolStatus(status int) bool {
	return status == 525 || status == 526 || status == 530
}

var errNoResponse = errors.New("no response")
