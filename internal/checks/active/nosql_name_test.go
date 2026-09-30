package active

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mongoNameSite answers the way a PHP front end over MongoDB does: the parameter
// name carries the operator, and the number of records follows from it.
func mongoNameSite(t *testing.T) *httptest.Server {
	t.Helper()
	const records = "<ul><li>alice</li><li>bob</li></ul>"
	const empty = "<p>no user</p>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		_, hasNe := q["user[$ne]"]
		_, hasExists := q["user[$exists]"]
		_, hasEq := q["user[$eq]"]
		body := empty
		switch {
		case hasNe && q.Get("user[$ne]") != "alice": // true of every document
			body = records
		case hasExists: // true of every document that has the field
			body = records
		case hasEq: // true of none
			body = empty
		case q.Get("user") == "alice": // the baseline query
			body = records
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", body)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestNoSQLFiresOnAParameterNameOperator: the whole injection is in the name, so
// a check that only rewrites values sends nothing that could find it.
func TestNoSQLFiresOnAParameterNameOperator(t *testing.T) {
	server := mongoNameSite(t)
	h := newHarness(t)
	findings := withParameter(t, h, nosqli{}, server.URL+"/login?user=alice")
	if len(findings) == 0 {
		t.Fatal("a target whose parameter name is read as a query operator was not reported")
	}
	if findings[0].Payload != "user[$ne]" {
		t.Errorf("payload = %q, want the operator spelling of the name", findings[0].Payload)
	}
}

// echoNameSite returns a different page for every request, quoting the raw query.
// The operators change the page as much as anything else does, so it is the
// "reproduce the baseline" half of the judgement that has to reject it.
func echoNameSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><p>results for: %s</p><p>nothing matched</p></body></html>",
			r.URL.RawQuery)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestNoSQLStaysQuietOnAPageThatEchoesTheName: each spelling produces its own
// page, so no two of them agree with the baseline and the finding is withheld.
func TestNoSQLStaysQuietOnAPageThatEchoesTheName(t *testing.T) {
	server := echoNameSite(t)
	h := newHarness(t)
	if findings := withParameter(t, h, nosqli{}, server.URL+"/login?user=alice"); len(findings) != 0 {
		t.Errorf("a page that echoes the name was reported: %v", findings[0].Evidence.Matches)
	}
}
