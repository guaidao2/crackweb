package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// TestMethodOverrideFiresWhenTheHeaderIsHonoured: the application acts on the
// header, so the response changes.
func TestMethodOverrideFiresWhenTheHeaderIsHonoured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verb := r.Header.Get("X-HTTP-Method-Override"); verb != "" {
			// The bug: a header decides what the request does.
			fmt.Fprintf(w, "<html><body>Performed %s. %s</body></html>", verb, strings.Repeat("done ", 40))
			return
		}
		fmt.Fprintf(w, "<html><body>Read only. %s</body></html>", strings.Repeat("page ", 40))
	}))
	defer server.Close()

	h := newHarness(t)
	findings := h.run(t, methodOverride{}, server.URL+"/items")
	if len(findings) == 0 {
		t.Fatal("an honoured method-override header was not reported")
	}
	if findings[0].CWE != "CWE-650" {
		t.Errorf("CWE = %q, want CWE-650", findings[0].CWE)
	}
	// The claim is deliberately weak: the header is honoured, whether that
	// crosses an authorisation boundary is not visible from here.
	if findings[0].Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative", findings[0].Confidence)
	}
}

// TestMethodOverrideStaysQuietWhenTheHeaderIsIgnored keeps the check from firing
// on every application.
func TestMethodOverrideStaysQuietWhenTheHeaderIsIgnored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>Read only. %s</body></html>", strings.Repeat("page ", 40))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := h.run(t, methodOverride{}, server.URL+"/items"); len(findings) != 0 {
		t.Errorf("a header the application ignores was reported: %+v", findings)
	}
}

// TestSmugglingProbesAreWellFormed checks the bytes, since a malformed probe
// would simply be rejected and look like a target that is not vulnerable.
func TestSmugglingProbesAreWellFormed(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.com/items?page=2")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	clte := string(buildCLTEProbe(request))
	if !strings.HasPrefix(clte, "POST /items?page=2 HTTP/1.1\r\n") {
		t.Errorf("CL.TE probe has a bad request line:\n%s", clte)
	}
	if !strings.Contains(clte, "Content-Length: ") || !strings.Contains(clte, "Transfer-Encoding: chunked") {
		t.Errorf("CL.TE probe does not carry both framing headers:\n%s", clte)
	}
	// The hidden request is what a desynchronised back end would read next.
	if !strings.Contains(clte, "GET /items?page=2 HTTP/1.1") {
		t.Errorf("CL.TE probe carries no follow-on request:\n%s", clte)
	}
	if !strings.HasSuffix(clte, "\r\n\r\n") {
		t.Errorf("CL.TE probe does not end with a blank line:\n%q", clte)
	}

	tecl := string(buildTECLProbe(request))
	if !strings.Contains(tecl, "Transfer-Encoding: chunked") || !strings.Contains(tecl, "Content-Length: ") {
		t.Errorf("TE.CL probe does not carry both framing headers:\n%s", tecl)
	}
	if !strings.Contains(tecl, "\r\n0\r\n\r\n") {
		t.Errorf("TE.CL probe has no chunked terminator:\n%s", tecl)
	}
}

func TestCountHTTPResponses(t *testing.T) {
	one := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	if got := countHTTPResponses(one); got != 1 {
		t.Errorf("countHTTPResponses(one) = %d, want 1", got)
	}

	two := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" +
		"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	if got := countHTTPResponses(two); got != 2 {
		t.Errorf("countHTTPResponses(two) = %d, want 2", got)
	}

	// A status line quoted inside a body is not a response: it has no CRLF after
	// it, which is what a real header block always has.
	embedded := []byte("HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n<pre>HTTP/1.1 200 OK</pre>")
	if got := countHTTPResponses(embedded); got != 1 {
		t.Errorf("countHTTPResponses(embedded) = %d, want 1", got)
	}

	// And the shape a desynchronised connection actually produces: the second
	// response starts immediately after the first one's body.
	backToBack := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" +
		"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
	if got := countHTTPResponses(backToBack); got != 2 {
		t.Errorf("countHTTPResponses(back-to-back) = %d, want 2", got)
	}

	if got := countHTTPResponses(nil); got != 0 {
		t.Errorf("countHTTPResponses(nil) = %d, want 0", got)
	}
}

// TestSmugglingIsUnsafeAndNotSelectedByDefault is the contract that keeps a
// probe with side effects off a target nobody asked about.
func TestSmugglingIsUnsafeAndNotSelectedByDefault(t *testing.T) {
	check := checks.ByID("request-smuggling")
	if check == nil {
		t.Fatal("the smuggling check is not registered")
	}
	if !checks.IsUnsafe(check) {
		t.Error("the smuggling check is not marked unsafe")
	}

	// "all" must not pull it in.
	selected, _ := checks.Select([]string{"all"})
	for _, candidate := range selected {
		if candidate.ID() == "request-smuggling" {
			t.Error("the smuggling check was selected by --checks all")
		}
	}

	// Naming it is the consent.
	named, unknown := checks.Select([]string{"request-smuggling"})
	if len(unknown) != 0 {
		t.Errorf("naming the check reported it as unknown: %v", unknown)
	}
	if len(named) != 1 || named[0].ID() != "request-smuggling" {
		t.Error("naming the smuggling check did not select it")
	}

	// The explicit flag includes it even under "all".
	withUnsafe, _ := checks.SelectFrom(checks.All(), []string{"all"}, true)
	found := false
	for _, candidate := range withUnsafe {
		if candidate.ID() == "request-smuggling" {
			found = true
		}
	}
	if !found {
		t.Error("the unsafe flag did not include the smuggling check")
	}
}

// TestMethodOverrideSkipsUnstablePage: if two back-to-back requests to the same
// URL disagree, no comparison against this page means anything, and reporting a
// difference would report the page's own noise.
func TestMethodOverrideSkipsUnstablePage(t *testing.T) {
	var counter int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&counter, 1)
		fmt.Fprintf(w, "<html><body>Counter %d %s</body></html>", n, strings.Repeat("dynamic ", 60))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := h.run(t, methodOverride{}, server.URL+"/live"); len(findings) != 0 {
		t.Errorf("a page that changes on every request was reported: %+v", findings[0].Evidence.Matches)
	}
}

// TestMethodOverrideSkipsHeadersThatChangeEverything: a target that reacts to
// any new header is not a target that reads the override header, and the control
// header is what tells the two apart.
func TestMethodOverrideSkipsHeadersThatChangeEverything(t *testing.T) {
	var (
		mu    sync.Mutex
		seen  = map[string]bool{}
		order []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Any header at all changes the page — but the override header beyond
		// that does nothing.
		extra := ""
		for _, name := range []string{"X-HTTP-Method-Override", "X-Crackweb-Control"} {
			if r.Header.Get(name) != "" {
				extra = name
			}
		}
		mu.Lock()
		if !seen[extra] {
			seen[extra] = true
			order = append(order, extra)
		}
		mu.Unlock()

		if extra != "" {
			fmt.Fprintf(w, "<html><body>Header seen: %s %s</body></html>", extra, strings.Repeat("variant ", 60))
			return
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", strings.Repeat("default ", 60))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := h.run(t, methodOverride{}, server.URL+"/echo"); len(findings) != 0 {
		t.Errorf("a page that reacts to any header was reported: %+v", findings[0].Evidence.Matches)
	}
}

// TestMethodOverrideIgnoresAServerError: a 5xx while the baseline was a 200 is a crash, not
// the application acting on the header. Comparing the error page against the control page
// says only that one request failed — and a single transient 5xx was enough to produce this
// finding on a target that ignores the header entirely.
func TestMethodOverrideIgnoresAServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range methodOverrideHeaders {
			if r.Header.Get(header) != "" {
				// A crash, not a refusal: a different status code from the baseline, so the
				// "same status as the baseline" guard does not catch it.
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "<html><body>Internal Server Error</body></html>")
				return
			}
		}
		fmt.Fprintf(w, "<html><body>Read only. %s</body></html>", strings.Repeat("page ", 40))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := h.run(t, methodOverride{}, server.URL+"/items"); len(findings) != 0 {
		t.Errorf("a server error was reported as an honoured override: %v", findings[0].Evidence.Matches)
	}
}
