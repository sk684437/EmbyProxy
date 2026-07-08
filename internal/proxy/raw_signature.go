package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	rawLinkURLParam = "__ep_raw_url"
	rawLinkExpParam = "__ep_raw_exp"
	rawLinkSigParam = "__ep_raw_sig"
	rawLinkTTL      = 24 * time.Hour
)

func newRawLinkKey(adminToken string) []byte {
	token := strings.TrimSpace(adminToken)
	if token != "" {
		sum := sha256.Sum256([]byte("embyproxy/raw-link/" + token))
		return append([]byte(nil), sum[:]...)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err == nil {
		return key
	}
	sum := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	return append([]byte(nil), sum[:]...)
}

func (h *Handler) rawSigningKey() []byte {
	if h == nil {
		return newRawLinkKey("")
	}
	if len(h.rawLinkKey) != 0 {
		return h.rawLinkKey
	}
	h.rawLinkKeyMu.Lock()
	defer h.rawLinkKeyMu.Unlock()
	if len(h.rawLinkKey) == 0 {
		h.rawLinkKey = newRawLinkKey(h.cfg.AdminToken)
	}
	return h.rawLinkKey
}

func (h *Handler) signedRawLink(origin, selfPrefix, raw string) string {
	exp := time.Now().Add(rawLinkTTL).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(raw))
	q := url.Values{}
	q.Set(rawLinkURLParam, payload)
	q.Set(rawLinkExpParam, strconv.FormatInt(exp, 10))
	q.Set(rawLinkSigParam, h.rawLinkSignature(selfPrefix, payload, exp))
	return origin + selfPrefix + "/__raw__?" + q.Encode()
}

func (h *Handler) signedRawURLFromQuery(r *http.Request, selfPrefix string) (string, bool) {
	if r == nil || r.URL == nil {
		return "", false
	}
	payloadValues, ok := r.URL.Query()[rawLinkURLParam]
	if !ok {
		return "", false
	}
	if len(payloadValues) != 1 {
		return "", false
	}
	payload := payloadValues[0]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	return string(raw), h.validRawLinkSignature(r, selfPrefix, payload)
}

func (h *Handler) validRawLinkSignature(r *http.Request, selfPrefix, payload string) bool {
	if r == nil || r.URL == nil {
		return false
	}
	if stripRawLinkSignatureQuery(r.URL.RawQuery) != "" {
		return false
	}
	q := r.URL.Query()
	expValues := q[rawLinkExpParam]
	sigValues := q[rawLinkSigParam]
	if len(expValues) != 1 || len(sigValues) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(expValues[0], 10, 64)
	if err != nil || exp < time.Now().Unix() {
		return false
	}
	want := h.rawLinkSignature(selfPrefix, payload, exp)
	return hmac.Equal([]byte(sigValues[0]), []byte(want))
}

func (h *Handler) rawLinkSignature(selfPrefix, payload string, exp int64) string {
	mac := hmac.New(sha256.New, h.rawSigningKey())
	mac.Write([]byte(selfPrefix))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(strconv.FormatInt(exp, 10)))
	mac.Write([]byte{'\n'})
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func requestWithoutRawLinkSignature(r *http.Request) *http.Request {
	if r == nil || r.URL == nil {
		return r
	}
	rawQuery := stripRawLinkSignatureQuery(r.URL.RawQuery)
	if _, ok := r.URL.Query()[rawLinkURLParam]; ok {
		rawQuery = ""
	}
	if rawQuery == r.URL.RawQuery {
		return r
	}
	copyReq := new(http.Request)
	*copyReq = *r
	copyURL := *r.URL
	copyURL.RawQuery = rawQuery
	copyReq.URL = &copyURL
	return copyReq
}

func stripRawLinkSignatureQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	keep := make([]string, 0, len(parts))
	for _, part := range parts {
		key := part
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			key = part[:idx]
		}
		if decoded, err := url.QueryUnescape(key); err == nil {
			key = decoded
		}
		if key == rawLinkURLParam || key == rawLinkExpParam || key == rawLinkSigParam {
			continue
		}
		keep = append(keep, part)
	}
	return strings.Join(keep, "&")
}

func rawRoutePrefixFromRequest(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	path := r.URL.EscapedPath()
	rawIdx := strings.Index(path, "/__raw__")
	if rawIdx < 0 {
		return ""
	}
	after := rawIdx + len("/__raw__")
	if after < len(path) && path[after] != '/' {
		return ""
	}
	return path[:rawIdx]
}
