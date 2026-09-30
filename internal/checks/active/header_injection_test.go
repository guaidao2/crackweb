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

// headerTarget builds a target for a request that carries a parameter, since the check is
// dispatched against one — the header is an additional place the application may read from, not
// a replacement for the parameter.
func headerTarget(t *testing.T, server *httptest.Server) *checks.Target {
	t.Helper()
	request, err := httpmsg.NewRequest("GET", server.URL+"/visit?page=home")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	return &checks.Target{Request: request, Response: response, Param: &params[0]}
}

// TestHeaderInjectionFiresOnAQueryBuiltFromAHeader: the parameter is harmless and the query is
// built from the forwarded address, which no parameter check can reach.
func TestHeaderInjectionFiresOnAQueryBuiltFromAHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded := r.Header.Get("X-Forwarded-For")
		if strings.Contains(forwarded, "CONVERT") || strings.HasSuffix(forwarded, "'") {
			fmt.Fprint(w, "<pre>mysqli error: You have an error in your SQL syntax near "+
				"'"+r.UserAgent()+"')' at line 1</pre>")
			return
		}
		fmt.Fprint(w, "<pre>logged<br>visits: 3</pre>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, sqliError{}, headerTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a query built from a header was not reported")
	}
	if !strings.Contains(findings[0].Payload, "X-Forwarded-For") {
		t.Errorf("payload = %q, want the header the payload was carried in", findings[0].Payload)
	}
	if findings[0].CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", findings[0].CWE)
	}
}

// TestHeaderInjectionNamesTheHeaderThatDid it: the payload has to say which header, because
// "some header" is not something a reader can act on.
func TestHeaderInjectionNamesTheHeaderThatDidIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Real-IP"), "'") {
			fmt.Fprint(w, "<pre>mysqli error: You have an error in your SQL syntax</pre>")
			return
		}
		fmt.Fprint(w, "<pre>logged</pre>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, sqliError{}, headerTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a query built from X-Real-IP was not reported")
	}
	if !strings.Contains(findings[0].Payload, "X-Real-IP") {
		t.Errorf("payload = %q, want the header that actually produced the error", findings[0].Payload)
	}
}

// TestHeaderInjectionStaysQuietWhenNoQueryUsesAHeader is the common case: one extra request.
func TestHeaderInjectionStaysQuietWhenNoQueryUsesAHeader(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, "<html><body>home</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, sqliError{}, headerTarget(t, server)); len(findings) != 0 {
		t.Errorf("a target that reads no header was reported: %v", findings[0].Payload)
	}
	// The parameter probes are the bulk; what matters is that the header walk did not add a
	// request per header in the negative case.
	if requests > 60 {
		t.Errorf("the scan spent %d requests on a target with nothing to find", requests)
	}
}

// TestPathInjectionFiresOnARouteThatReadsTheSegment: the parameter is harmless and the query is
// built from the route, which is where a RESTful application puts the value.
func TestPathInjectionFiresOnARouteThatReadsTheSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		segment := segments[len(segments)-1]
		// The route as it is addressed normally, plus a resource that simply is not there.
		if segment == "visit" || segment == "admin" || segment == "nope" {
			fmt.Fprint(w, "<pre>rows: 0</pre>")
			return
		}
		// A quote in the segment breaks the statement, exactly as it would in a parameter.
		fmt.Fprint(w, "<pre>mysqli error: You have an error in your SQL syntax near "+
			"'"+segment+"' at line 1</pre>")
	}))
	defer server.Close()

	h := newHarness(t)
	findings := runRequestLevel(t, h, sqliError{}, headerTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a query built from a path segment was not reported")
	}
	if !strings.Contains(findings[0].Payload, "path segment") {
		t.Errorf("payload = %q, want the payload to say where it was put", findings[0].Payload)
	}
}

// TestPathInjectionStaysQuietOnAMissingResource: a segment that does not exist is served
// normally and says nothing about a query, which is the bound that keeps this from reporting
// every route on every site.
func TestPathInjectionStaysQuietOnAMissingResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Not Found</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := runRequestLevel(t, h, sqliError{}, headerTarget(t, server)); len(findings) != 0 {
		t.Errorf("a missing resource was read as an injection: %v", findings[0].Payload)
	}
}

// TestWithPathPayloadKeepsTheEscapingToTheURL: the payload goes in as it stands, because the URL
// escapes Path when the request is written. Escaping it here as well put the escapes on the wire
// — `%2527` where `%27` was meant — and the request that was sent asked for a different segment
// than the one that was judged.
func TestWithPathPayloadKeepsTheEscapingToTheURL(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.test/user/admin?page=2")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	out, ok := withPathPayload(request, "'", true)
	if !ok {
		t.Fatal("the payload was not placed")
	}
	raw := string(out.Raw())
	if strings.Contains(raw, "%2527") {
		t.Errorf("the segment was escaped twice: %s", raw)
	}
	if !strings.Contains(raw, "%27") {
		t.Errorf("the segment was not escaped at all: %s", raw)
	}
	// The rest of the request is untouched.
	if !strings.Contains(raw, "page=2") {
		t.Errorf("the query string was changed: %s", raw)
	}
}
