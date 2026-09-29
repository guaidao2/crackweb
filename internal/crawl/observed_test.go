package crawl

import (
	"encoding/base64"
	"testing"

	"github.com/chromedp/cdproto/network"

	"github.com/guaidao2/crackweb/internal/scope"
)

// newTestCrawler builds a crawler scoped to one host without starting a browser.
func newTestCrawler(t *testing.T, host string) *Crawler {
	t.Helper()
	c := New(Options{})
	c.scope = scope.NewScope([]string{host})
	return c
}

func TestRequestBodyReassemblesTheEntries(t *testing.T) {
	// The protocol hands a body over as base64 entries, and a JSON document is what makes
	// reassembling it worth the trouble.
	request := &network.Request{
		HasPostData: true,
		PostDataEntries: []*network.PostDataEntry{
			{Bytes: base64.StdEncoding.EncodeToString([]byte(`{"user":"alice",`))},
			{Bytes: base64.StdEncoding.EncodeToString([]byte(`"note":"hi"}`))},
		},
	}
	if got, want := string(requestBody(request)), `{"user":"alice","note":"hi"}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestRequestBodyRefusesWhatItCannotRebuild(t *testing.T) {
	cases := map[string]*network.Request{
		"no post data":        {HasPostData: false},
		"no entries":          {HasPostData: true},
		"an undecodable part": {HasPostData: true, PostDataEntries: []*network.PostDataEntry{{Bytes: "not base64!"}}},
	}
	for name, request := range cases {
		if body := requestBody(request); body != nil {
			t.Errorf("%s: got %q, want nil — a half-rebuilt request tests something the browser never sent", name, body)
		}
	}
}

func TestRequestBodyIsBounded(t *testing.T) {
	oversized := make([]byte, maxObservedBody+1)
	request := &network.Request{
		HasPostData:     true,
		PostDataEntries: []*network.PostDataEntry{{Bytes: base64.StdEncoding.EncodeToString(oversized)}},
	}
	if body := requestBody(request); body != nil {
		t.Errorf("an oversized body was kept (%d bytes)", len(body))
	}
}

func TestRequestContentTypeIsReadCaseInsensitively(t *testing.T) {
	request := &network.Request{
		Headers: network.Headers{"content-TYPE": "application/json; charset=utf-8"},
	}
	if got, want := requestContentType(request), "application/json; charset=utf-8"; got != want {
		t.Errorf("content type = %q, want %q", got, want)
	}
}

func TestWorthReplaying(t *testing.T) {
	cases := []struct {
		name string
		item observedRequest
		want bool
	}{
		{
			name: "a JSON POST is what the HTTP engine cannot produce",
			item: observedRequest{URL: "http://x/api", Method: "POST", Body: []byte(`{"a":1}`)},
			want: true,
		},
		{
			name: "a PUT carrying a body counts too",
			item: observedRequest{URL: "http://x/api", Method: "PUT", Body: []byte(`{"a":1}`)},
			want: true,
		},
		{
			name: "a GET is the HTTP engine's own job",
			item: observedRequest{URL: "http://x/api", Method: "GET", Body: []byte("a=1")},
			want: false,
		},
		{
			name: "a bodyless POST has nothing to test and an effect to repeat",
			item: observedRequest{URL: "http://x/logout", Method: "POST"},
			want: false,
		},
		{
			name: "an oversized body is an upload",
			item: observedRequest{URL: "http://x/api", Method: "POST", Body: make([]byte, maxReplayBody+1)},
			want: false,
		},
	}
	for _, tc := range cases {
		if got := tc.item.worthReplaying(); got != tc.want {
			t.Errorf("%s: worthReplaying() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestReplayObservedDropsWhatIsOutOfScope checks the filtering the browser's observations go
// through before anything is sent again.
func TestReplayObservedDropsWhatIsOutOfScope(t *testing.T) {
	c := newTestCrawler(t, "example.com")
	if got := c.replayObserved(t.Context(), []observedRequest{
		{URL: "http://other.example.net/api", Method: "POST", Body: []byte(`{"a":1}`)},
		{URL: "http://example.com/logout", Method: "POST"},
		{URL: "mailto:someone@example.com", Method: "POST", Body: []byte("x=1")},
	}); got != 0 {
		t.Errorf("replayed %d requests, want 0: none of them is an in-scope request with a body", got)
	}
}
