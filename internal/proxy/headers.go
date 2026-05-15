package proxy

import (
	"net/http"
	"net/url"
	"regexp"
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

func stripClientIPHeaders(h http.Header) {
	for _, key := range []string{"X-Forwarded-For", "X-Real-IP", "True-Client-IP", "Forwarded", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port"} {
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
	h.Set("Access-Control-Allow-Private-Network", "true")
	h.Set("Access-Control-Max-Age", "86400")
	h.Set("Cache-Control", "no-store")
	if ao != "*" {
		h.Set("Access-Control-Allow-Credentials", "true")
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
		cookie = regexp.MustCompile(`(?i);\s*domain=[^;]+`).ReplaceAllString(cookie, "")
		if prefix != "" {
			if regexp.MustCompile(`(?i);\s*path=`).MatchString(cookie) {
				cookie = regexp.MustCompile(`(?i);\s*path=[^;]+`).ReplaceAllString(cookie, "; Path="+prefix)
			} else {
				cookie += "; Path=" + prefix
			}
		}
		headers.Add("Set-Cookie", cookie)
	}
}

func copyResponseHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		lower := strings.ToLower(key)
		if lower == "transfer-encoding" || lower == "content-encoding" || lower == "content-length" || lower == "content-md5" {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isDecodedBodyHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-encoding", "content-length", "content-md5":
		return true
	default:
		return false
	}
}
