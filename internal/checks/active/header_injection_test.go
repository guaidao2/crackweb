package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/finding"
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

// ---------------------------------------------------------------------------------------------
// Blind injection through a header and through the path

// blindRows evaluates a condition appended to a value the way a database would, which is what
// makes the test targets below databases rather than lookup tables: any two conditions with the
// same truth value have to answer identically, and any two with different ones differently.
func blindRows(base int, value string) int {
	rows := base
	if m := conditionRe.FindStringSubmatch(value); m != nil {
		op := strings.ToUpper(m[1])
		equal := strings.EqualFold(m[2], m[3])
		switch {
		case op == "OR" && equal:
			rows = 39 // always true, so the whole table
		case op == "AND" && !equal:
			rows = 0 // always false
		}
	}
	return rows
}

// blindPage renders a page whose content follows the row count, so a difference in the result set
// is a difference in the response.
func blindPage(w http.ResponseWriter, label string, rows int) {
	body := "<html><body><p>" + label + "</p><table>"
	for i := 0; i < rows; i++ {
		body += "<tr><td>row</td></tr>"
	}
	fmt.Fprint(w, body+"</table></body></html>")
}

// TestBlindBooleanFiresOnAHeaderBuiltQuery: the parameter is harmless and the query is built from
// the forwarded address. Nothing in the response says "error" and nothing about the page is
// unusual — the row count moves with the condition, which is the whole of the evidence.
func TestBlindBooleanFiresOnAHeaderBuiltQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// `SELECT * FROM visits WHERE ip = '<forwarded>'`, with a table that holds no row for
		// the address this request sent.
		blindPage(w, "visits", blindRows(0, r.Header.Get("X-Forwarded-For")))
	}))
	defer server.Close()

	h := newHarness(t)
	findings := (sqliBoolean{}).Run(context.Background(), h.ctx, headerTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a query built from a header was not reported by the boolean check")
	}
	checkEvidenceCarriesPayload(t, findings)
	if !strings.Contains(findings[0].Payload, "X-Forwarded-For") {
		t.Errorf("payload = %q, want the header that carried it", findings[0].Payload)
	}
	if findings[0].CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", findings[0].CWE)
	}
	if findings[0].Confidence != finding.ConfidenceFirm {
		t.Errorf("confidence = %q, want the confidence a confirmation pair earns", findings[0].Confidence)
	}
}

// TestBlindBooleanFiresOnARouteThatReadsTheSegment: the same flaw written in the path. The
// resource the route addresses holds no row, so only a condition that widens the result set can
// move the page.
func TestBlindBooleanFiresOnARouteThatReadsTheSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		segment := segments[len(segments)-1]
		blindPage(w, "users", blindRows(0, segment))
	}))
	defer server.Close()

	h := newHarness(t)
	findings := (sqliBoolean{}).Run(context.Background(), h.ctx, headerTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a query built from a path segment was not reported by the boolean check")
	}
	checkEvidenceCarriesPayload(t, findings)
	if !strings.Contains(findings[0].Payload, "path segment") {
		t.Errorf("payload = %q, want the payload to say where it was put", findings[0].Payload)
	}
}

// TestBlindBooleanStaysQuietAndCheapWhenNothingReadsAHeader: the common case, bounded. A walk that
// finished every family at every one of the five headers would cost five times what this does;
// what keeps it to one pass is the combined screen, whose first pair is the pair the family walk
// would have started with anyway.
func TestBlindBooleanStaysQuietAndCheapWhenNothingReadsAHeader(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		blindPage(w, "home", 3)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := (sqliBoolean{}).Run(context.Background(), h.ctx, headerTarget(t, server)); len(findings) != 0 {
		t.Errorf("a target that reads no header and no segment was reported: %v", findings[0].Payload)
	}
	if requests > 120 {
		t.Errorf("the check spent %d requests on a target with nothing to find", requests)
	}
}

// TestBlindTimeFiresOnAHeaderThatPauses: a header reaching a statement that can be told to wait.
//
// The spellings are shortened to a second so the test does not spend five per sample. What is being
// tested is the check's own machinery — the screen, the attribution to one header, and the control
// the measurement is taken against — and the verdict comes from JudgeTiming either way.
func TestBlindTimeFiresOnAHeaderThatPauses(t *testing.T) {
	const pause = time.Second
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Forwarded-For"), "SLEEP(1)") {
			time.Sleep(pause)
		}
		fmt.Fprint(w, "<html><body>visited</body></html>")
	}))
	defer server.Close()

	spellings := []blindDelay{
		{"' AND SLEEP(" + blindPauseToken + ")-- -", pause},
		{" AND SLEEP(" + blindPauseToken + ")-- -", pause},
	}

	h := newHarness(t)
	f := blindTimingFinding(context.Background(), h.ctx, headerTarget(t, server), spellings)
	if f == nil {
		t.Fatal("a header that paused the target was not reported by the time-based check")
	}
	if f.CheckID != "sqli-time" {
		t.Errorf("check = %q, want the time-based check's id", f.CheckID)
	}
	if !strings.Contains(f.Payload, "X-Forwarded-For") {
		t.Errorf("payload = %q, want the header that carried it", f.Payload)
	}
	checkEvidenceCarriesPayload(t, []*finding.Finding{f})
}

// TestBlindTimeStaysQuietOnATargetThatDoesNotPause: a target that answers at once, bounded. The
// header screen is one request per spelling, not one per spelling per header.
func TestBlindTimeStaysQuietOnATargetThatDoesNotPause(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, "<html><body>visited</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	if f := blindTimingFinding(context.Background(), h.ctx, headerTarget(t, server), blindDelaySpellings); f != nil {
		t.Errorf("a target that never pauses was reported: %v", f.Payload)
	}
	if requests > 30 {
		t.Errorf("the check spent %d requests on a target that cannot pause", requests)
	}
}

// TestBlindDelaySpellingsCoverBothQuotingContexts: a quote opens a string position and is a syntax
// error in a numeric one, so a place that lands in either has to be written for it. The mistake
// this guards against once left every numeric parameter invisible to the time-based check.
func TestBlindDelaySpellingsCoverBothQuotingContexts(t *testing.T) {
	var quoted, bare bool
	for _, spelling := range blindDelaySpellings {
		if strings.HasPrefix(spelling.payload, "'") {
			quoted = true
		} else {
			bare = true
		}
		if spelling.pause < 5*time.Second {
			t.Errorf("%q asks for %v, which is not worth a measurement", spelling.payload, spelling.pause)
		}
		if !strings.Contains(spelling.payload, "SLEEP(") {
			continue
		}
		if !strings.Contains(spelling.payload, blindPauseToken) {
			t.Errorf("%q does not take its pause from the number the verdict expects", spelling.payload)
		}
	}
	if !quoted || !bare {
		t.Errorf("quoting contexts covered: quoted=%v bare=%v", quoted, bare)
	}
}

// TestBlindFamiliesCarryTheWidenedQuoteAsAByte: the transport-form families spell the wide byte as
// percent escapes, which a header sends literally and a path escapes a second time. Written as the
// byte, the same pair reaches both.
func TestBlindFamiliesCarryTheWidenedQuoteAsAByte(t *testing.T) {
	var wide bool
	for _, family := range blindFamilies() {
		if family.encoded {
			t.Errorf("family %q is in transport form, which the blind probe does not send", family.name)
		}
		for _, value := range family.trueValues {
			if strings.Contains(value, "%df") {
				t.Errorf("family %q carries a percent escape, which means nothing in a header", family.name)
			}
			if strings.Contains(value, "\xdf") {
				wide = true
			}
		}
	}
	if !wide {
		t.Error("no family writes the widened byte as a byte: a GBK target would never be seen")
	}
}

// TestBlindPathSiteWritesIntoTheSegmentTheRouteReads: the payload goes where the resource name is,
// because a value appended after it names a different resource and a different route answers.
func TestBlindPathSiteWritesIntoTheSegmentTheRouteReads(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.test/user/admin?page=2")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	site, ok := blindPathSite(&checks.Target{Request: request})
	if !ok {
		t.Fatal("the segment the route reads was not found")
	}
	if site.original != "admin" {
		t.Errorf("original = %q, want the segment the request addressed", site.original)
	}
	out, ok := site.write(site.prefix() + "' OR '1'='1'-- -")
	if !ok {
		t.Fatal("the payload was not placed")
	}
	if got := out.URL.Path; got != "/user/admin' OR '1'='1'-- -" {
		t.Errorf("path = %q, want the payload in place of the last segment", got)
	}
	if !strings.Contains(string(out.Raw()), "page=2") {
		t.Error("the query string was changed")
	}
	if !strings.Contains(site.payload("x"), "path segment") {
		t.Error("the payload does not say where it was put")
	}
}

// ---------------------------------------------------------------------------------------------
// The two things a blind finding rests on: a control measured the same way, and a place named
// exactly. Neither is relaxed because the value arrived somewhere other than a parameter.

// TestBlindControlLeavesTheRequestAsItStands pins the control the delay verdict is measured
// against.
//
// A time-based finding is the difference between two measurements, so the control has to be the
// same request with nothing written into it — not the same request with a harmless value, which
// would compare one spelling of the payload against another. It is also why the value handed to it
// is ignored: whatever the spelling under test, the control is the request as it stands.
func TestBlindControlLeavesTheRequestAsItStands(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.test/visit?page=home")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	target := &checks.Target{Request: request}

	control := blindControl(target)
	for _, value := range []string{"", "1' AND SLEEP(5)-- -", "visit' AND SLEEP(5)-- -"} {
		out, ok := control.write(value)
		if !ok || out == nil {
			t.Fatalf("the control refused the value %q", value)
		}
		if got := out.URLString(); got != "http://example.test/visit?page=home" {
			t.Errorf("the control changed the address to %q", got)
		}
		if got := out.Header.Get("X-Forwarded-For"); got != "203.0.113.9" {
			t.Errorf("the control changed X-Forwarded-For to %q", got)
		}
		if got, want := len(out.Header.All()), len(request.Header.All()); got != want {
			t.Errorf("the control has %d fields, want the request's %d", got, want)
		}
	}
}

// TestBlindHeaderSitesCarryTheHeadersOwnValue: a place extends the value it already held and names
// its own header.
//
// Both jobs matter downstream. The value it held is what a reflected payload is restored to before
// two branches are compared, and the name is what the finding is attributed to: a walk that wrote
// into the right header but reported "X-Forwarded-For" because that heads the list would send a
// reader to the wrong place entirely.
func TestBlindHeaderSitesCarryTheHeadersOwnValue(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.test/visit?page=home")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	target := &checks.Target{Request: request}

	sites := blindHeaderSites(target)
	if len(sites) != len(sqliHeaderNames) {
		t.Fatalf("%d places for %d candidate headers", len(sites), len(sqliHeaderNames))
	}
	for _, site := range sites {
		if !strings.Contains(site.label, site.header) {
			t.Errorf("the place %q does not name the header %q it writes", site.label, site.header)
		}
		if got := site.original; got != request.Header.Get(site.header) {
			t.Errorf("%s: original = %q, want the value the header already held", site.header, got)
		}
		if payload := site.payload(site.prefix() + "'"); !strings.Contains(payload, site.header) {
			t.Errorf("%s: the payload %q does not name the header", site.header, payload)
		}
	}

	// The address is carried through; the headers that held nothing start from the neutral value a
	// condition can be appended to.
	forwarded := sites[0]
	if forwarded.header != "X-Forwarded-For" {
		t.Fatalf("the first place writes %q, want the header the error-based probe tries first", forwarded.header)
	}
	if got := forwarded.prefix(); got != "203.0.113.9" {
		t.Errorf("prefix = %q, want the value the header already held", got)
	}
	out, ok := forwarded.write(forwarded.prefix() + "' AND '1'='1")
	if !ok || out == nil {
		t.Fatal("the payload was not written into the header")
	}
	if got := out.Header.Get("X-Forwarded-For"); got != "203.0.113.9' AND '1'='1" {
		t.Errorf("X-Forwarded-For = %q, want the payload appended to the value it held", got)
	}
	if got := out.Header.Get("X-Real-IP"); got != "" {
		t.Errorf("X-Real-IP = %q, want it untouched by a write into another header", got)
	}
	if got := sites[1].prefix(); got != "1" {
		t.Errorf("a header that held nothing extends %q, want the neutral value", got)
	}
}

// TestBlindTimingIgnoresATargetThatIsAlwaysSlow is the control, tested where it matters.
//
// The screen cannot tell this target from an injected one: the probe request takes four hundred
// milliseconds, which is all the screen asks. What refuses the finding is the control measured the
// same way — the identical request with nothing written into the header — whose median moves with
// the injected one, leaving no difference attributable to the payload.
func TestBlindTimingIgnoresATargetThatIsAlwaysSlow(t *testing.T) {
	const pause = time.Second
	// Slower than the screen's quarter-of-the-pause threshold, and the same every single time.
	const slow = 400 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(slow)
		fmt.Fprint(w, "<html><body>visited</body></html>")
	}))
	defer server.Close()

	spellings := []blindDelay{{"' AND SLEEP(" + blindPauseToken + ")-- -", pause}}
	h := newHarness(t)
	target := headerTarget(t, server)
	site := blindHeaderSites(target)[0]

	if f := blindTimingAt(context.Background(), h.ctx, target, site, spellings); f != nil {
		t.Errorf("a target that is slow whatever it is sent was reported: %v", f.Payload)
	}
}

// TestBlindTimeFiresOnARouteThatPauses covers the other arm of the same check: the delay reached
// through the path rather than a header.
//
// The route reads its resource from the last segment, which is the ordinary shape of a RESTful
// application and a place no parameter reaches. The spellings are shortened to a second for the
// same reason as the header test above: what is under test is the place, the control and the
// attribution, and the verdict comes from JudgeTiming either way.
func TestBlindTimeFiresOnARouteThatPauses(t *testing.T) {
	const pause = time.Second
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if strings.Contains(segments[len(segments)-1], "SLEEP(1)") {
			time.Sleep(pause)
		}
		fmt.Fprint(w, "<html><body>user</body></html>")
	}))
	defer server.Close()

	spellings := []blindDelay{{"' AND SLEEP(" + blindPauseToken + ")-- -", pause}}
	h := newHarness(t)
	f := blindTimingFinding(context.Background(), h.ctx, headerTarget(t, server), spellings)
	if f == nil {
		t.Fatal("a route that paused the target was not reported by the time-based check")
	}
	if f.CheckID != "sqli-time" {
		t.Errorf("check = %q, want the time-based check's id", f.CheckID)
	}
	if !strings.Contains(f.Payload, "path") {
		t.Errorf("payload = %q, want the payload to say where it was put", f.Payload)
	}
	// The evidence quotes the delay the payload asked for, because that number is what makes the
	// finding reproducible rather than a slow afternoon on the target.
	if f.Evidence.Duration < pause*7/10 {
		t.Errorf("evidence duration = %v, want the pause the payload asked for", f.Evidence.Duration)
	}
	checkEvidenceCarriesPayload(t, []*finding.Finding{f})
}

// TestBlindBooleanNamesTheRefererHeader: the walk reaches every candidate header, not just the one
// that heads the list, and the finding names the header that actually carried the payload.
func TestBlindBooleanNamesTheRefererHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// `SELECT * FROM referrals WHERE source = '<Referer>'`, with a table that holds no row
		// for the page this request came from.
		blindPage(w, "referrals", blindRows(0, r.Header.Get("Referer")))
	}))
	defer server.Close()

	h := newHarness(t)
	findings := (sqliBoolean{}).Run(context.Background(), h.ctx, headerTarget(t, server))
	if len(findings) == 0 {
		t.Fatal("a query built from the Referer header was not reported by the boolean check")
	}
	if !strings.Contains(findings[0].Payload, "Referer") {
		t.Errorf("payload = %q, want the header that actually carried it", findings[0].Payload)
	}
	checkEvidenceCarriesPayload(t, findings)
}

// TestBlindBooleanStaysQuietOnAPageThatVaries is the same bound the parameter walk has, held at the
// places a parameter cannot reach.
//
// Every response here is different from every other, which is what a counter, a clock or an
// advertisement does to a page. No family can pass its own consistency test — two equally true
// conditions never answer alike — so nothing is reported, and the check does not need a separate
// round of repeat requests to find that out.
func TestBlindBooleanStaysQuietOnAPageThatVaries(t *testing.T) {
	served := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		blindPage(w, "feed", served)
	}))
	defer server.Close()

	h := newHarness(t)
	if findings := (sqliBoolean{}).Run(context.Background(), h.ctx, headerTarget(t, server)); len(findings) != 0 {
		t.Errorf("a page that changes on every request was read as a boolean channel: %v", findings[0].Payload)
	}
}

// TestBlindTimingVerdictRefusesWhatCannotBeReproduced pins the thresholds a blind delay finding
// inherits from the parameter walk.
//
// Nothing here is a request: it is the arithmetic the check hands to JudgeTiming, asserted so that
// the blind places cannot quietly become easier to report than the parameter one. The added delay
// has to reach what the payload asked for, stand clear of the noise, and reproduce across
// measurements — and a target that is merely slow fails all three at once, because its control
// moves with it.
func TestBlindTimingVerdictRefusesWhatCannotBeReproduced(t *testing.T) {
	control := summariseDurations([]time.Duration{
		40 * time.Millisecond, 41 * time.Millisecond, 42 * time.Millisecond,
		43 * time.Millisecond, 44 * time.Millisecond,
	})

	reproducible := summariseDurations([]time.Duration{
		1040 * time.Millisecond, 1041 * time.Millisecond, 1042 * time.Millisecond,
		1043 * time.Millisecond, 1044 * time.Millisecond,
	})
	if verdict := checks.JudgeTiming(control, reproducible, time.Second); !verdict.Delayed {
		t.Fatalf("a reproducible one-second pause was refused: %s", verdict.Reason)
	}

	jittery := summariseDurations([]time.Duration{
		200 * time.Millisecond, 300 * time.Millisecond, 900 * time.Millisecond,
		1200 * time.Millisecond, 1400 * time.Millisecond,
	})
	if verdict := checks.JudgeTiming(control, jittery, time.Second); verdict.Delayed {
		t.Errorf("an inconsistent pause was reported: %s", verdict.Reason)
	}

	// A target that takes four hundred milliseconds whatever it is sent: the control says so, and
	// the difference is nothing.
	slow := summariseDurations([]time.Duration{
		400 * time.Millisecond, 401 * time.Millisecond, 402 * time.Millisecond,
		403 * time.Millisecond, 404 * time.Millisecond,
	})
	slowInjected := summariseDurations([]time.Duration{
		405 * time.Millisecond, 406 * time.Millisecond, 407 * time.Millisecond,
		408 * time.Millisecond, 409 * time.Millisecond,
	})
	if verdict := checks.JudgeTiming(slow, slowInjected, time.Second); verdict.Delayed {
		t.Errorf("a target that is merely slow was reported: %s", verdict.Reason)
	}

	// A pause that overshoots what was asked for is somebody else's slow request, not the payload.
	overshoot := summariseDurations([]time.Duration{
		1900 * time.Millisecond, 1901 * time.Millisecond, 1902 * time.Millisecond,
		1903 * time.Millisecond, 1904 * time.Millisecond,
	})
	if verdict := checks.JudgeTiming(control, overshoot, time.Second); verdict.Delayed {
		t.Errorf("a delay larger than the payload could have produced was reported: %s", verdict.Reason)
	}
}
