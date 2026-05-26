package proxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackedBody struct {
	reader *strings.Reader
	closed bool
}

func newTrackedBody(value string) *trackedBody {
	return &trackedBody{reader: strings.NewReader(value)}
}

func (b *trackedBody) Read(p []byte) (int, error) {
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

func TestFetchWithProtocolFallbackClosesDiscardedFirstResponse(t *testing.T) {
	firstBody := newTrackedBody("first")
	secondBody := newTrackedBody("second")
	schemes := []string{}

	h := &Handler{
		manualClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			schemes = append(schemes, req.URL.Scheme)
			if len(schemes) == 1 {
				return &http.Response{StatusCode: 530, Header: http.Header{}, Body: firstBody, Request: req}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: secondBody, Request: req}, nil
		})},
	}

	target, err := url.Parse("https://example.test/emby/System/Info")
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.fetchWithProtocolFallback(context.Background(), target, http.MethodGet, http.Header{}, nil, false)
	if err != nil {
		t.Fatalf("fetchWithProtocolFallback() error = %v", err)
	}
	t.Cleanup(func() {
		_ = res.Body.Close()
	})
	if res.Body != secondBody {
		t.Fatal("fetchWithProtocolFallback() did not return the fallback response")
	}
	if got := strings.Join(schemes, ","); got != "https,http" {
		t.Fatalf("schemes = %q, want https,http", got)
	}
	if !firstBody.closed {
		t.Fatal("discarded first response body was not closed")
	}
	if secondBody.closed {
		t.Fatal("returned response body was closed too early")
	}
}

func TestSetLastResponseClosesReplacedResponse(t *testing.T) {
	h := &Handler{}
	firstBody := newTrackedBody("first")
	secondBody := newTrackedBody("second")
	first := &http.Response{Body: firstBody}
	second := &http.Response{Body: secondBody}

	var last *http.Response
	h.setLastResponse(&last, first)
	if last != first {
		t.Fatal("first response was not stored")
	}
	if firstBody.closed {
		t.Fatal("stored response body was closed")
	}

	h.setLastResponse(&last, second)
	if last != second {
		t.Fatal("second response was not stored")
	}
	if !firstBody.closed {
		t.Fatal("replaced response body was not closed")
	}
	if secondBody.closed {
		t.Fatal("replacement response body was closed")
	}
}
