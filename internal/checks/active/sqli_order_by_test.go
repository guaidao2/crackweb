package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/diff"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// orderSiteColumnCount is how many columns the simulated query returns. It is the
// boundary the check probes: a term naming one of these is a valid sort term, and
// a term past the end is not.
const orderSiteColumnCount = 3

// orderQuery simulates the statement a sorting endpoint builds: the application's
// own clause, with the caller's value appended as one more term.
//
// The second result is whether the query ran. A term naming a column the result
// set does not have makes the whole statement fail, which is the behaviour the
// check exists to observe — and the behaviour that only a sorting clause has:
// the same term inside a quoted string is text, and in a numeric comparison the
// statement has already failed on the term before it.
//
// columns is how many columns the query returns, and it is a parameter rather
// than a constant because the check must not assume a width: a one-column query
// is a shape real endpoints have, and its boundary is one term away.
func orderQuery(order string, columns int) (int, bool) {
	terms := strings.Split(order, ",")
	switch strings.ToLower(strings.TrimSpace(terms[0])) {
	case "id", "id asc", "id desc", "name", "name asc", "name desc":
	default:
		return 0, false
	}
	for _, term := range terms[1:] {
		position, err := strconv.Atoi(strings.TrimSpace(term))
		if err != nil || position < 1 || position > columns {
			return 0, false
		}
	}
	return columns, true
}

// orderPage renders the result of a sorting query. A failed query renders the
// same page with no rows, which is what the real thing does: the error is
// swallowed and the reader sees an empty table.
func orderPage(rows int) string {
	var b strings.Builder
	b.WriteString(`<html><body><table>`)
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&b, "<tr><td>row %d</td><td>a</td><td>b</td></tr>", i)
	}
	b.WriteString(`</table><p>sorted</p></body></html>`)
	return b.String()
}

// firstQueryValue returns the value of a request's only parameter, whatever it is
// called. The name is deliberately not part of any of these harnesses: what the
// check decides has to come from the answers, not from the spelling.
func firstQueryValue(r *http.Request) string {
	for _, values := range r.URL.Query() {
		if len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// orderBySite is a target whose sort parameter reaches the query, over a result
// set three columns wide.
func orderBySite(t *testing.T) *httptest.Server {
	return orderBySiteWithColumns(t, orderSiteColumnCount)
}

// orderBySiteWithColumns is the same target over a result set of a given width.
func orderBySiteWithColumns(t *testing.T, columns int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		rows, ok := orderQuery(firstQueryValue(r), columns)
		if !ok {
			fmt.Fprint(w, orderPage(0))
			return
		}
		fmt.Fprint(w, orderPage(rows))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestSQLiOrderByFiresOnASortingClause(t *testing.T) {
	server := orderBySite(t)
	h := newHarness(t)
	findings := withParameter(t, h, sqliOrderBy{}, server.URL+"/users?order=id+desc")

	if len(findings) == 0 {
		t.Fatal("an injectable sort parameter was not reported")
	}
	f := findings[0]
	// The payload has to be the value that produced the evidence: the whole point
	// of the finding is that a reader can replay it.
	if !strings.Contains(f.Payload, outOfRangeTerms[0]) {
		t.Errorf("payload = %q, want the value that was refused (%q)", f.Payload, outOfRangeTerms[0])
	}
	if !strings.Contains(string(f.Evidence.Request), url.QueryEscape(f.Payload)) {
		t.Errorf("the evidence request does not carry the payload %q:\n%s", f.Payload, f.Evidence.Request)
	}
	if len(f.Evidence.Response) == 0 || len(f.Evidence.Baseline) == 0 {
		t.Error("evidence is incomplete")
	}
	if f.Evidence.Diff == "" {
		t.Error("no difference was described")
	}
	if len(f.Evidence.Matches) == 0 {
		t.Error("no evidence matches were recorded")
	}
	if f.CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", f.CWE)
	}
}

// TestSQLiOrderByFiresWhateverTheParameterIsCalled is the reason the check reads
// no parameter names: a sort column is called whatever its author called it, and
// a check that only looked at names containing "order" or "sort" would miss the
// injection in every application that spells it another way.
func TestSQLiOrderByFiresWhateverTheParameterIsCalled(t *testing.T) {
	server := orderBySite(t)
	h := newHarness(t)

	for _, target := range []string{
		"/users?c=id+desc",
		"/users?col=id+desc",
		"/users?by=id+desc",
		"/users?f=id+desc",
		"/users?_s=id+desc",
		"/users?q=id+desc",
	} {
		findings := withParameter(t, h, sqliOrderBy{}, server.URL+target)
		if len(findings) == 0 {
			t.Errorf("%s: a sorting clause behind an unremarkable parameter name was not reported", target)
			continue
		}
		if !strings.Contains(findings[0].Payload, outOfRangeTerms[0]) {
			t.Errorf("%s: payload = %q, want the refused term", target, findings[0].Payload)
		}
	}
}

// TestSQLiOrderByFiresOnAOneColumnQuery: the boundary is discovered, not assumed.
// A query that returns a single column has no room for a second sort term, and
// its refusal is the same boundary the far term hits — a check that required the
// second term to be accepted would skip every one-column endpoint, which is a
// shape real applications have.
func TestSQLiOrderByFiresOnAOneColumnQuery(t *testing.T) {
	server := orderBySiteWithColumns(t, 1)
	h := newHarness(t)
	findings := withParameter(t, h, sqliOrderBy{}, server.URL+"/users?order=id+desc")

	if len(findings) == 0 {
		t.Fatal("a one-column query behind a sort parameter was not reported")
	}
	// The evidence has to be the term that was actually refused.
	if !strings.Contains(findings[0].Payload, inRangeTerms[1]) {
		t.Errorf("payload = %q, want the boundary term %q", findings[0].Payload, inRangeTerms[1])
	}
}

// TestSQLiOrderByIgnoresAWhitelistedSort: an endpoint that maps the value onto
// the columns it allows refuses every appended term, so nothing about the
// position can be observed — and reporting it would be reporting the refusal.
func TestSQLiOrderByIgnoresAWhitelistedSort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// The safe implementation: anything but the exact allowed values is
		// refused, and the page is the empty result of a query that never ran.
		switch firstQueryValue(r) {
		case "id desc", "id asc", "name desc", "name asc":
			fmt.Fprint(w, orderPage(orderSiteColumnCount))
		default:
			fmt.Fprint(w, orderPage(0))
		}
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, sqliOrderBy{}, server.URL+"/users?sort=id+desc"); len(findings) != 0 {
		t.Errorf("a whitelisted sort parameter was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestSQLiOrderByIgnoresAStringContext is the case the old judgement reported as
// ORDER BY injection: the value lands in a quoted string, so a term appended to
// it is text and the query answers normally. The string check reports the
// injection; the sorting position does not exist here.
func TestSQLiOrderByIgnoresAStringContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// `name = '<value>'`: every value is a valid string, appended terms included.
		fmt.Fprintf(w, `%s<p>results for %s</p>`,
			orderPage(orderSiteColumnCount), strings.ReplaceAll(firstQueryValue(r), `<`, "&lt;"))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, sqliOrderBy{}, server.URL+"/search?name=id+desc"); len(findings) != 0 {
		t.Errorf("a string context was reported as a sorting clause: %v", findings[0].Evidence.Matches)
	}
}

// TestSQLiOrderByIgnoresANumericContext: `id = <value>,99` is a syntax error,
// but so is `id = <value>,1` — the in-range term fails first, so the position is
// not a sort list whatever the out-of-range answer looks like.
func TestSQLiOrderByIgnoresANumericContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if _, err := strconv.Atoi(firstQueryValue(r)); err != nil {
			fmt.Fprint(w, orderPage(0))
			return
		}
		fmt.Fprint(w, orderPage(orderSiteColumnCount))
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, sqliOrderBy{}, server.URL+"/users?id=1"); len(findings) != 0 {
		t.Errorf("a numeric context was reported as a sorting clause: %v", findings[0].Evidence.Matches)
	}
}

// TestSQLiOrderByIgnoresAPageThatMerelyContainsTheValue: the page carries
// `size="1"` of its own and the parameter is ignored, so nothing about a sorting
// clause can be observed. The echo restore used to shorten the probe's
// fingerprint here — `1"` matches inside `size="1"` — and invent a difference;
// the companion test below pins that symmetry directly.
func TestSQLiOrderByIgnoresAPageThatMerelyContainsTheValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><input name="order" size="1"><p>`+
			orderPage(orderSiteColumnCount)+`</p></body></html>`)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := withParameter(t, h, sqliOrderBy{}, server.URL+"/users?order=id"); len(findings) != 0 {
		t.Errorf("a page that merely quotes a `1\"` sequence was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestEchoRestoreIsAppliedToBothSides pins the property the comparison rests on,
// independently of any check: the same restore list on both fingerprints makes a
// reflection look like the baseline, and on one side only it invents a
// difference out of page text the application wrote itself.
func TestEchoRestoreIsAppliedToBothSides(t *testing.T) {
	h := newHarness(t)
	header := httpmsg.NewHeader(httpmsg.KV{Name: "Content-Type", Value: "text/html"})
	// `size="1"` contains `1"`, which is the whole difficulty: the replacement
	// matches it whether or not anything was reflected.
	baseline := &httpmsg.Response{Status: 200, Header: header,
		Body: []byte(`<html><body><input size="1"><p>` + strings.Repeat("row ", 20) + `1</p></body></html>`)}
	probe := &httpmsg.Response{Status: 200, Header: header,
		Body: []byte(`<html><body><input size="1"><p>` + strings.Repeat("row ", 20) + `1"</p></body></html>`)}

	pairs := echoRestore(`1"`, `1`)
	bothSides := diff.CompareFingerprints(h.ctx.Fingerprint(baseline, pairs...), h.ctx.Fingerprint(probe, pairs...)).Score
	if bothSides < 0.999 {
		t.Errorf("the restore is not symmetric: score=%.4f", bothSides)
	}

	oneSide := diff.CompareFingerprints(h.ctx.Fingerprint(baseline), h.ctx.Fingerprint(probe, pairs...)).Score
	if oneSide >= 0.999 {
		t.Error("a one-sided restore did not produce a difference, so this test cannot catch the mistake")
	}
}

// TestSQLiOrderByCostsAnUnrelatedParameterTwoRequests: asking every parameter is
// what keeps the coverage honest, so the cost has to be bounded by the order the
// questions are asked in. A value that never reaches a query accepts both the
// in-range and the out-of-range term, and the second answer ends the check before
// the confirming pair is spent.
func TestSQLiOrderByCostsAnUnrelatedParameterTwoRequests(t *testing.T) {
	var requests int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		w.Header().Set("Content-Type", "text/html")
		// The application ignores the parameter, so every term is accepted.
		fmt.Fprint(w, orderPage(orderSiteColumnCount))
	}))
	defer server.Close()

	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/users?q=hello")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	atomic.StoreInt64(&requests, 0)
	findings := (sqliOrderBy{}).Run(context.Background(), h.ctx, target)
	spent := atomic.LoadInt64(&requests)

	if len(findings) != 0 {
		t.Fatalf("an unrelated parameter was reported: %v", findings[0].Evidence.Matches)
	}
	if spent != 2 {
		t.Errorf("the check spent %d request(s) on a value that is not a sort term, want 2", spent)
	}
}

// TestSQLiOrderByNeedsAValueToAppendTo: `ORDER BY ,1` is not a sort term, so a
// parameter with nothing in it has no position to test.
func TestSQLiOrderByNeedsAValueToAppendTo(t *testing.T) {
	server := orderBySite(t)
	h := newHarness(t)

	request, err := httpmsg.NewRequest("GET", server.URL+"/users?order=")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	if findings := (sqliOrderBy{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("an empty sort value was reported: %v", findings[0].Evidence.Matches)
	}
}
