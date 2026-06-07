package proxy

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"embyproxy/internal/config"
	"embyproxy/internal/identity"
	"embyproxy/internal/storage"
)

func cloneHeader(in http.Header) http.Header {
	out := http.Header{}
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}

// These headers commonly carry client addresses or proxy-derived routing metadata.
var clientIPHeaderNames = []string{
	"Forwarded",
	"Forwarded-For",
	"X-Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-For-Original",
	"X-Forwarded-For-Proxy-Protocol",
	"X-Forwarded-IP",
	"X-Forwarded-Client-IP",
	"X-Original-Forwarded-For",
	"X-Forward-For",
	"X-Real-IP",
	"True-Client-IP",
	"CF-Connecting-IP",
	"CF-Connecting-IPv6",
	"CF-Pseudo-IPv4",
	"Fastly-Client-IP",
	"CloudFront-Viewer-Address",
	"X-Azure-ClientIP",
	"X-Azure-SocketIP",
	"X-Envoy-External-Address",
	"Ali-Cdn-Real-IP",
	"Ali-Real-Client-IP",
	"Akamai-Client-IP",
	"Client-IP",
	"ClientIP",
	"Client-Real-IP",
	"Real-IP",
	"Real-Client-IP",
	"X-Client-IP",
	"X-Client-Real-IP",
	"X-Cluster-Client-IP",
	"X-Originating-IP",
	"X-Original-IP",
	"X-Original-Remote-Addr",
	"X-Real-Client-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"Proxy-Client-IP",
	"WL-Proxy-Client-IP",
	"X-ProxyUser-IP",
	"X-Appengine-User-IP",
	"Remote-Addr",
	"Remote-Host",
	"HTTP-Client-IP",
	"HTTP-X-Forwarded-For",
	"HTTP-X-Forwarded",
	"HTTP-X-Real-IP",
	"HTTP-X-Cluster-Client-IP",
	"HTTP-Forwarded-For",
	"HTTP-Forwarded",
	"HTTP_CLIENT_IP",
	"HTTP_X_FORWARDED_FOR",
	"HTTP_X_FORWARDED",
	"HTTP_X_REAL_IP",
	"HTTP_X_CLUSTER_CLIENT_IP",
	"HTTP_FORWARDED_FOR",
	"HTTP_FORWARDED",
	"REMOTE_ADDR",
	"X-Forwarded-Proto",
	"X-Forwarded-Host",
	"X-Forwarded-Port",
}

func stripClientIPHeaders(h http.Header) {
	for _, key := range clientIPHeaderNames {
		h.Del(key)
	}
}

func deleteHeaders(h http.Header, keys ...string) {
	for _, key := range keys {
		h.Del(key)
	}
}

func setProxyUA(ids *identity.Manager, h http.Header, node storage.Node, clientUA string) {
	ua := strings.TrimSpace(clientUA)
	if node.Impersonate {
		ua = ids.Snapshot(node.ImpersonateProfile).UserAgent
	}
	if ua == "" {
		h.Del("User-Agent")
		return
	}
	h.Set("User-Agent", ua)
}

func applyIdentity(ids *identity.Manager, h http.Header, node storage.Node, setEmbyIdentity bool) {
	if node.Impersonate {
		ids.ApplyToHeaders(h, node.ImpersonateProfile, setEmbyIdentity)
	}
}

func applyIdentityToURL(ids *identity.Manager, u *url.URL, node storage.Node) {
	if node.Impersonate {
		ids.ApplyToURL(u, node.ImpersonateProfile)
	}
}

func buildCleanProxyHeaders(ids *identity.Manager, raw http.Header, targetURL *url.URL, node storage.Node, env config.ProxyEnv, streaming bool) http.Header {
	h := cloneHeader(raw)
	stripClientIPHeaders(h)
	deleteHeaders(h, "Connection", "Content-Length")
	if !streaming {
		deleteHeaders(h, "Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User")
	}
	h.Set("Host", targetURL.Host)
	setProxyUA(ids, h, node, raw.Get("User-Agent"))
	h.Set("Accept-Encoding", "identity")
	applyIdentity(ids, h, node, true)
	if rg := raw.Get("Range"); rg != "" {
		h.Set("Range", rg)
	}
	if ifRange := raw.Get("If-Range"); ifRange != "" {
		h.Set("If-Range", ifRange)
	}
	if isEmosNode(node, targetURL, env) {
		applyEmosHeaders(h, env)
	}
	return h
}

func buildDirectOutboundHeaders(ids *identity.Manager, raw http.Header, targetURL *url.URL, env config.ProxyEnv, node storage.Node, mode string) http.Header {
	h := cloneHeader(raw)
	adapter := directAdapter(targetURL)
	stripClientIPHeaders(h)
	deleteHeaders(h,
		"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port",
		"Forwarded", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Connection", "Content-Length", "Origin", "Referer",
	)
	h.Set("Host", targetURL.Host)
	setProxyUA(ids, h, node, raw.Get("User-Agent"))
	h.Set("Accept-Encoding", "identity")
	applyIdentity(ids, h, node, true)
	if rg := raw.Get("Range"); rg != "" {
		h.Set("Range", rg)
	}
	if ifRange := raw.Get("If-Range"); ifRange != "" {
		h.Set("If-Range", ifRange)
	}
	if adapter.Referer != "" && (!adapter.KeepReferer || h.Get("Referer") == "") {
		h.Set("Referer", adapter.Referer)
	}
	if !adapter.KeepOrigin {
		h.Del("Origin")
	} else if adapter.Referer != "" {
		if ref, err := url.Parse(adapter.Referer); err == nil {
			h.Set("Origin", ref.Scheme+"://"+ref.Host)
		}
	}
	if mode == "retry-no-origin" {
		h.Del("Origin")
		h.Del("Referer")
	}
	if mode == "retry-browserish" {
		setProxyUA(ids, h, node, raw.Get("User-Agent"))
		if h.Get("Referer") == "" && adapter.KeepReferer && adapter.Referer != "" {
			h.Set("Referer", adapter.Referer)
		}
	}
	if isEmosNode(node, targetURL, env) {
		applyEmosHeaders(h, env)
	}
	return h
}

func pickAllowOrigin(reqOrigin, allow string) string {
	allow = strings.TrimSpace(allow)
	if reqOrigin == "" {
		return "*"
	}
	if allow == "" {
		return reqOrigin
	}
	if allow == "*" {
		return "*"
	}
	for _, item := range strings.Split(allow, ",") {
		if strings.TrimSpace(item) == reqOrigin {
			return reqOrigin
		}
	}
	return "null"
}

func addCORSHeaders(headers http.Header, reqOrigin string, env config.ProxyEnv) {
	ao := pickAllowOrigin(reqOrigin, env.CORSAllowOrigin)
	headers.Set("Access-Control-Allow-Origin", ao)
	if ao != "*" {
		headers.Set("Vary", "Origin")
	}
}

func sendCORSPreflight(w http.ResponseWriter, reqOrigin string, env config.ProxyEnv) {
	h := w.Header()
	ao := pickAllowOrigin(reqOrigin, env.CORSAllowOrigin)
	h.Set("Access-Control-Allow-Origin", ao)
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Max-Age", "86400")
	h.Set("Cache-Control", "no-store")
	if ao != "*" {
		h.Set("Vary", "Origin")
	}
	w.WriteHeader(http.StatusOK)
}

func rewriteSetCookieHeaders(headers http.Header, prefix string) {
	cookies := headers.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	headers.Del("Set-Cookie")
	for _, cookie := range cookies {
		cookie = setCookieDomainRE.ReplaceAllString(cookie, "")
		if prefix != "" {
			if setCookiePathPresentRE.MatchString(cookie) {
				cookie = setCookiePathRE.ReplaceAllString(cookie, "; Path="+prefix)
			} else {
				cookie += "; Path=" + prefix
			}
		}
		headers.Add("Set-Cookie", cookie)
	}
}

func copyResponseHeaders(dst http.Header, src http.Header, bodyDecoded bool) {
	skipContentLength := bodyDecoded || src.Get("Content-Encoding") != "" || src.Get("Transfer-Encoding") != ""
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "transfer-encoding" || lower == "content-encoding" || lower == "content-md5" {
			continue
		}
		if lower == "content-length" && skipContentLength {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func fillContentLengthFromContentRange(headers http.Header) {
	if headers == nil || strings.TrimSpace(headers.Get("Content-Length")) != "" {
		return
	}
	m := contentRangeBytesRE.FindStringSubmatch(strings.TrimSpace(headers.Get("Content-Range")))
	if len(m) != 4 {
		return
	}
	start, errStart := strconv.ParseInt(m[1], 10, 64)
	end, errEnd := strconv.ParseInt(m[2], 10, 64)
	if errStart != nil || errEnd != nil || start < 0 || end < start {
		return
	}
	headers.Set("Content-Length", strconv.FormatInt(end-start+1, 10))
}

func isDecodedBodyHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-encoding", "content-length", "content-md5":
		return true
	default:
		return false
	}
}
