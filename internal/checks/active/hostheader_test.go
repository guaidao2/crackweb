package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

func hostTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/account")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	return &checks.Target{Request: request, Response: response}
}

// TestHostHeaderStaysQuietOnAPageThatDumpsTheRequest: PHP's $_SERVER spells a request header
// `HTTP_HOST`, and a page built on it that prints its variables writes every header that way.
// Recognising only the name as it was sent leaves such a page looking as though it used the
// value.
func TestHostHeaderStaysQuietOnAPageThatDumpsTheRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// The shape a real dump page has: several values before this one, each with its own
		// colon, and the header's own line somewhere in the middle.
		fmt.Fprintf(w, "<html><body><p>param q: hi</p><p>header HTTP_X_FORWARDED_HOST: 127.0.0.1</p>"+
			"<p>header HTTP_HOST: %s</p><p>path: /account</p>", r.Host)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, hostHeader{}, hostTarget(t, server)); len(findings) != 0 {
		t.Errorf("a page that dumped the request was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestHostHeaderFiresWhenTheValueBuildsALink is the other side: the canary is in the page, and it
// is in a position the application produced rather than one it copied.
func TestHostHeaderFiresWhenTheValueBuildsALink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><a href=\"http://%s/reset?token=abc\">Reset</a></body></html>", r.Host)
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, hostHeader{}, hostTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a host used to build a link was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "crackweb-host-check.invalid") {
		t.Errorf("the evidence does not name the value that was used: %v", findings[0].Evidence.Matches)
	}
}
