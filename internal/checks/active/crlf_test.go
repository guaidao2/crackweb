package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// echoingRedirectSite writes the parameter straight into a Location header, and
// writes the response by hand so the injected line really does become a header.
// `net/http` refuses to emit a header value carrying CRLF, which is exactly why
// the vulnerable shape cannot be simulated with Header().Set.
func echoingRedirectSite(t *testing.T, decode func(string) string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("redirect")
		if decode != nil {
			value = decode(value)
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the test server cannot hijack")
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(buffered, "HTTP/1.1 302 Found\r\nLocation: /%s\r\nContent-Length: 0\r\n\r\n", value)
		buffered.Flush()
	}))
	t.Cleanup(server.Close)
	return server
}

// TestCRLFFiresOnAnEchoingRedirect: the header the check introduces arrives as a
// header, which is the only observation that proves splitting.
func TestCRLFFiresOnAnEchoingRedirect(t *testing.T) {
	server := echoingRedirectSite(t, nil)
	h := newHarness(t)
	findings := withParameter(t, h, crlfInjection{}, server.URL+"/?redirect=/home")
	if len(findings) == 0 {
		t.Fatal("a redirect that copied the parameter into a header was not reported")
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), crlfHeaderName) {
		t.Errorf("evidence does not name the injected header: %v", findings[0].Evidence.Matches)
	}
}

// TestCRLFFiresThroughTheOverlongEncoding: a front end that decodes the UTF-8
// form of U+560D/U+560A and keeps the low byte turns it into CR LF. A filter
// written against `\r`, `\n` and `%0d` has nothing to match, and the header
// still separates.
func TestCRLFFiresThroughTheOverlongEncoding(t *testing.T) {
	server := echoingRedirectSite(t, func(value string) string {
		return strings.ReplaceAll(value, "\xe5\x98\x8d\xe5\x98\x8a", "\r\n")
	})
	h := newHarness(t)
	findings := withParameter(t, h, crlfInjection{}, server.URL+"/?redirect=/home")
	if len(findings) == 0 {
		t.Fatal("a front end that decodes the overlong form was not reported")
	}
}
