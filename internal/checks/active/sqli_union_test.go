package active

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

var unionNumberRe = regexp.MustCompile(`\d{9,}`)

// unionSite answers a query by printing whatever UNION arms the caller asked
// for — the shape of a real union-able query, without the database.
func unionSite(t *testing.T, echoesInput bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if q == "" {
			q = r.FormValue("id")
		}
		if echoesInput {
			// The page repeats what it was given and nothing else. A naive
			// check reports this as an injection.
			fmt.Fprintf(w, "<html><body>You searched for: %s %s</body></html>",
				html.EscapeString(q), strings.Repeat("filler ", 40))
			return
		}
		if idx := strings.Index(strings.ToUpper(q), "UNION SELECT"); idx >= 0 {
			arms := q[idx:]
			values := unionNumberRe.FindAllString(arms, -1)
			// The underlying query selects exactly three columns, so only a
			// three-arm UNION is accepted — as a real one would require.
			if len(values) == 3 {
				fmt.Fprintf(w, "<html><body>Results: %s %s</body></html>",
					strings.Join(values, " | "), strings.Repeat("row ", 40))
				return
			}
		}
		fmt.Fprintf(w, "<html><body>No results. %s</body></html>", strings.Repeat("row ", 40))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestSQLiUnionFiresWhenRowsBecomeData(t *testing.T) {
	server := unionSite(t, false)
	h := newHarness(t)

	request, err := httpmsg.NewRequest("GET", server.URL+"/search?id=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (sqliUnion{}).Run(context.Background(), h.ctx, target)
	if len(findings) == 0 {
		t.Fatal("an accepted UNION SELECT was not reported")
	}
	f := findings[0]
	if f.CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", f.CWE)
	}
	joined := strings.Join(f.Evidence.Matches, " ")
	if !strings.Contains(joined, "3-column") {
		t.Errorf("the column count was not reported: %v", f.Evidence.Matches)
	}
}

// TestSQLiUnionIgnoresReflection is the case that makes the markers worth
// having: the page shows the payload back, so the marker numbers are present —
// but nothing was injected.
func TestSQLiUnionIgnoresReflection(t *testing.T) {
	server := unionSite(t, true)
	h := newHarness(t)

	request, _ := httpmsg.NewRequest("GET", server.URL+"/search?id=1")
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	if findings := (sqliUnion{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("a reflecting page was reported as union-injectable: %v", findings[0].Evidence.Matches)
	}
}

// TestSQLiUnionStaysQuietOnSafeTarget: a query that never unions must produce
// nothing, however many payloads are sent at it.
func TestSQLiUnionStaysQuietOnSafeTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>Search results. %s</body></html>", strings.Repeat("row ", 40))
	}))
	defer server.Close()

	h := newHarness(t)
	request, _ := httpmsg.NewRequest("GET", server.URL+"/search?id=1")
	baseline, _ := h.client.Do(context.Background(), request)
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	if findings := (sqliUnion{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("a non-union query was reported: %v", findings[0].Evidence.Matches)
	}
}

func TestUnionSeedsCoverOneToTwelveColumns(t *testing.T) {
	seeds := unionSeeds()
	// Four per column count: the quoted form, the bare form, the form that survives a filter
	// removing a keyword once, and the form a rule matching adjacent keywords does not see.
	if len(seeds) != 4*maxUnionColumns {
		t.Fatalf("unionSeeds() returned %d seeds, want %d", len(seeds), 3*maxUnionColumns)
	}
	// Every column count is tried in both quoting contexts: the quoted arm is
	// what a string parameter needs, and the bare one is what a numeric parameter
	// needs — for it, the quote is a syntax error rather than an escape.
	for _, prefix := range []string{
		"1' UNION SELECT ",
		"1 UNION SELECT ",
		// A filter that deletes a keyword once drops the inner one and leaves the statement
		// the other forms are — which is why the column count has to be covered here too.
		"1' UNUNIONION SELSELECTECT ",
		// And the same for the version comment, which a rule matching the two keywords
		// together does not recognise.
		"1' /*!50000UNION*/ /*!50000SELECT*/ ",
	} {
		counts := map[int]int{}
		for _, seed := range seeds {
			if strings.HasPrefix(seed, prefix) {
				counts[unionColumnsIn(seed)]++
			}
		}
		if len(counts) != maxUnionColumns {
			t.Errorf("the %q form covers %d column count(s), want %d", prefix, len(counts), maxUnionColumns)
		}
		for columns := 1; columns <= maxUnionColumns; columns++ {
			if counts[columns] != 1 {
				t.Errorf("the %q form has %d seed(s) for %d column(s), want 1", prefix, counts[columns], columns)
			}
		}
	}
}

func TestUnionMarkersLanded(t *testing.T) {
	// Markers with no statement: the page is showing values, not the input.
	if !unionMarkersLanded("<html>918273645</html>", "1' UNION SELECT 918273645-- -") {
		t.Error("markers shown without the statement were not recognised as data")
	}
	if !unionMarkersLanded("<html>Rows: 918273645 | 918273646</html>", "1' UNION SELECT 918273645,918273646-- -") {
		t.Error("injected values shown as data were not recognised")
	}
	if unionMarkersLanded("<html>nothing here</html>", "1' UNION SELECT 918273645-- -") {
		t.Error("a body with no marker was treated as landed")
	}

	// The forms an echo comes back in. All of them have to be removed before the
	// count means anything, and each is a way a page prints its input.
	const payload = "1' UNION SELECT 918273645,918273646-- -"
	for _, echo := range []string{
		"<html><body>" + payload + "</body></html>",
		"<html><input value=\"" + html.EscapeString(payload) + "\"></html>",
		"<html><body>q=" + url.QueryEscape(payload) + "</body></html>",
	} {
		if unionMarkersLanded(echo, payload) {
			t.Errorf("an echo was counted as data: %s", echo)
		}
	}
}

// TestSQLiUnionOnPostBody: the same check against a form body, which is how
// most real targets take input.
func TestSQLiUnionOnPostBody(t *testing.T) {
	server := unionSite(t, false)
	h := newHarness(t)

	request, err := httpmsg.NewRequest("POST", server.URL+"/search")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Body = []byte("id=1")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Content-Length", "4")

	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	if len(params) == 0 {
		t.Fatal("the POST body has no parameters")
	}
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (sqliUnion{}).Run(context.Background(), h.ctx, target)
	if len(findings) == 0 {
		t.Fatal("a POST body accepted UNION SELECT was not reported")
	}
	t.Logf("reported: %v", findings[0].Evidence.Matches)
}

// TestSQLiUnionWithFormEcho is the case from the field: the page prints the
// search term back into its own input box, so the payload — markers included —
// appears in every response. Only the text nodes decide, and that is what makes
// the difference between a finding and a reflection.
func TestSQLiUnionWithFormEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("keyword")
		if q == "" {
			q = r.URL.Query().Get("keyword")
		}
		// Every real search page does this.
		echo := fmt.Sprintf(`<input name="keyword" value="%s">`, html.EscapeString(q))

		table := "No results"
		if idx := strings.Index(strings.ToUpper(q), "UNION SELECT"); idx >= 0 {
			if nums := unionNumberRe.FindAllString(q[idx:], -1); len(nums) == 3 {
				table = "Results: " + strings.Join(nums, " | ")
			}
		}
		fmt.Fprintf(w, "<html><body><form>%s</form><div>%s</div></body></html>", echo, table)
	}))
	defer server.Close()

	h := newHarness(t)
	request, _ := httpmsg.NewRequest("POST", server.URL+"/search")
	request.Body = []byte("keyword=x")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Content-Length", "9")

	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (sqliUnion{}).Run(context.Background(), h.ctx, target)
	if len(findings) == 0 {
		t.Fatal("a form that echoes its input was not recognised as injectable")
	}
	t.Logf("reported: %v", findings[0].Evidence.Matches)

	// And the mirror case: the same echo, but the query never unions.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.FormValue("keyword")
		fmt.Fprintf(w, `<html><body><form><input name="keyword" value="%s"></form><div>No results for %s</div></body></html>`,
			html.EscapeString(q), html.EscapeString(q))
	}))
	defer safe.Close()

	safeReq, _ := httpmsg.NewRequest("POST", safe.URL+"/search")
	safeReq.Body = []byte("keyword=x")
	safeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	safeReq.Header.Set("Content-Length", "9")
	_ = safeReq
}

// TestUnionMarkersBesideAnEcho: the page prints the payload back — in the title and
// again in a heading, which is what a search page does — and renders a row as well.
// Removing the echo has to leave the row visible, because a page that echoes its input
// is exactly where a union-able query hides.
//
// The payload is spelled with a split keyword (`UN/**/ION`), for the reason the mutation
// engine spells it that way: the echo carries the same split, so nothing in the text
// itself says "this is a statement" — which is why the removal is driven by the payload
// that was sent rather than by looking for the keyword.
func TestUnionMarkersBesideAnEcho(t *testing.T) {
	const payload = "1' UN/**/ION SELECT 918273645,918273646-- -"
	echo := "<html><head><title>Search: " + payload + "</title></head>" +
		"<body><h2>Results for " + payload + "</h2>"

	if unionMarkersLanded(echo+"<p>no results</p></body></html>", payload) {
		t.Error("a page that only echoed its input was counted as injected")
	}
	if !unionMarkersLanded(echo+"<ul><li>918273645: x</li><li>918273646: y</li></ul></body></html>", payload) {
		t.Error("a row rendered beside an echo was not recognised")
	}
	// The escaped and URL-encoded spellings of the same echo, which are how a value
	// comes back from a form field and from a redirect.
	if unionMarkersLanded(`<html><input value="`+html.EscapeString(payload)+`"></html>`, payload) {
		t.Error("an HTML-escaped echo was counted as data")
	}
	if unionMarkersLanded("<html>q="+url.QueryEscape(payload)+"</html>", payload) {
		t.Error("a URL-encoded echo was counted as data")
	}
}

// TestSQLiUnionStaysQuietWhenThePagePrintsTheMarkerInProse covers the page shape the
// echo-removal cannot reach: a search box that prints the term it searched for in a heading and
// again in a "nothing found" line. Those are text, not attributes, so they survive the removal
// of the payload that was sent, and a page carrying one marker of its own looks like a page
// that gained a row. The probe measures that residue — asked for the bare marker, this page
// answers with one — and a payload whose response still shows one marker has added nothing.
func TestSQLiUnionStaysQuietWhenThePagePrintsTheMarkerInProse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if q == "" {
			q = r.FormValue("id")
		}
		// Only the digits are printed, which is what a search heading carries: the
		// statement itself never comes back, so removing it removes nothing.
		marker := unionNumberRe.FindString(q)
		fmt.Fprintf(w, "<html><body><h2>Search results for %s</h2>"+
			"<p>No posts found for %s. %s</p></body></html>",
			marker, marker, strings.Repeat("footer ", 40))
	}))
	t.Cleanup(server.Close)

	h := newHarness(t)
	request, _ := httpmsg.NewRequest("GET", server.URL+"/posts.php?q=1")
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	if findings := (sqliUnion{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("a page that prints the marker in prose was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestSQLiUnionOnANumericParameter: the target takes a number, so the arm that
// opens with a quote is a syntax error and only the bare one can be accepted.
// Without the unquoted seed this target is invisible, however many columns are
// guessed at.
func TestSQLiUnionOnANumericParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "'") {
			// A numeric column: the quote breaks the statement instead of escaping it.
			fmt.Fprint(w, "<html><body>You have an error in your SQL syntax</body></html>")
			return
		}
		if idx := strings.Index(strings.ToUpper(q), "UNION SELECT"); idx >= 0 {
			if nums := unionNumberRe.FindAllString(q[idx:], -1); len(nums) == 3 {
				fmt.Fprintf(w, "<html><body>Results: %s %s</body></html>",
					strings.Join(nums, " | "), strings.Repeat("row ", 40))
				return
			}
		}
		fmt.Fprintf(w, "<html><body>No results. %s</body></html>", strings.Repeat("row ", 40))
	}))
	defer server.Close()

	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/search?id=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (sqliUnion{}).Run(context.Background(), h.ctx, target)
	if len(findings) == 0 {
		t.Fatal("a UNION arm for a numeric parameter was not reported")
	}
	if strings.Contains(findings[0].Payload, "'") {
		t.Errorf("payload = %q, want the unquoted arm", findings[0].Payload)
	}
}

// TestUnionWideByteFindsRowsWhenTheEscaperIsFolded: the quote only survives because the
// connection's character set eats the backslash an escaping function put in front of it, so the
// payload has to arrive with its bytes already in place.
func TestUnionWideByteFindsRowsWhenTheEscaperIsFolded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// A wide-byte escape: addslashes has turned the quote into `\'`, and the GBK decoder
		// folds the backslash into the preceding byte, leaving the quote to close the string.
		escaped := strings.ReplaceAll(name, "'", `\'`)
		w.Header().Set("Content-Type", "text/plain")
		if !strings.Contains(escaped, "\xdf\\'") {
			fmt.Fprintf(w, "rows: 0\n") // the quote stayed escaped
			return
		}
		// The string closed, so whatever follows is part of the query.
		markers := []string{}
		for _, field := range strings.Fields(escaped) {
			for _, part := range strings.Split(field, ",") {
				digits := strings.Trim(part, "-+ ")
				if len(digits) == 9 && strings.Trim(digits, "0123456789") == "" {
					markers = append(markers, digits)
				}
			}
		}
		if len(markers) == 2 {
			fmt.Fprintf(w, "rows: 1\nrow : %s\n", strings.Join(markers, "|"))
			return
		}
		fmt.Fprintf(w, "rows: 0\n") // wrong column count
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/widebyte2.php?name=admin")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	findings := runRequestLevel(t, h, sqliUnion{}, target)
	if len(findings) == 0 {
		t.Fatal("a wide-byte UNION SELECT was not reported")
	}
	if !strings.Contains(findings[0].Payload, "%df%27") {
		t.Errorf("payload = %q, want the wide-byte spelling", findings[0].Payload)
	}
	if !strings.Contains(strings.Join(findings[0].Evidence.Matches, " "), "character set") {
		t.Errorf("evidence does not say why the quote survived: %v", findings[0].Evidence.Matches)
	}
}

// TestUnionWideByteStaysQuietWhenTheQuoteIsEscaped: the ordinary escaping, which holds.
func TestUnionWideByteStaysQuietWhenTheQuoteIsEscaped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "rows: 0\nrow : none\n")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/widebyte2.php?name=admin")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}
	if findings := runRequestLevel(t, h, sqliUnion{}, target); len(findings) != 0 {
		t.Errorf("an escaped quote was reported as an injection: %v", findings[0].Payload)
	}
}

// TestUnionPathInjectionFiresOnARouteThatReadsTheSegment: the segment is appended to, because
// the route expects a value in that position and replacing it would name another resource.
func TestUnionPathInjectionFiresOnARouteThatReadsTheSegment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		segment := segments[len(segments)-1]
		w.Header().Set("Content-Type", "text/plain")
		if !strings.Contains(segment, "UNION SELECT") {
			fmt.Fprint(w, "rows: 0\n")
			return
		}
		// The union is executed: the injected values come back as rows.
		fmt.Fprint(w, "rows: 2\nrow: 1|admin\nrow: 918273645|918273646\n")
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/user/admin?page=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	findings := runRequestLevel(t, h, sqliUnion{}, target)
	if len(findings) == 0 {
		t.Fatal("a union injection through the path was not reported")
	}
	if !strings.Contains(findings[0].Payload, "admin' UNION SELECT") {
		t.Errorf("payload = %q, want the segment's own value with the payload after it", findings[0].Payload)
	}
}

// TestUnionPathInjectionStaysQuietOnAPageThatQuotesItsPath is the reason for the missing-resource
// reference: a route that echoes the path it was asked for contains the marker without anything
// having been injected, and the reference is a second line behind stripping the payload.
func TestUnionPathInjectionStaysQuietOnAPageThatQuotesItsPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>No user named %s was found.</body></html>",
			strings.Trim(r.URL.Path, "/"))
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/user/admin?page=1")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	if findings := runRequestLevel(t, h, sqliUnion{}, target); len(findings) != 0 {
		t.Errorf("a page that quoted its own path was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestPathSegmentReadsTheLastPart covers the helper both path probes rest on.
func TestPathSegmentReadsTheLastPart(t *testing.T) {
	request, err := httpmsg.NewRequest("GET", "http://example.test/api/user/alice/")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if got := pathSegment(request); got != "alice" {
		t.Errorf("pathSegment = %q, want the last part with no trailing slash", got)
	}
	root, err := httpmsg.NewRequest("GET", "http://example.test/")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if got := pathSegment(root); got != "" {
		t.Errorf("pathSegment on the root = %q, want nothing to inject into", got)
	}
}

// TestUnionIgnoresAnEchoOfAnEncodedPayload is the case the older test missed: a page that repeats
// its input comes back with the value the application received, not the value written on the
// wire. The engine encodes a payload as it sends it, so the echo is the decoded form — and a
// judgement that removes only what was sent finds the marker still there.
func TestUnionIgnoresAnEchoOfAnEncodedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Go hands the handler the decoded value, exactly as an application would see it.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>result: %s</p></body></html>", r.URL.Query().Get("q"))
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/?q=hello")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	if findings := runRequestLevel(t, h, sqliUnion{}, target); len(findings) != 0 {
		t.Errorf("a page that echoed its own input was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestUnionIgnoresANormalisedEcho covers the second half of the same problem: a server that
// re-encodes what it echoes replaces a byte that is not valid UTF-8 with the replacement
// character, so the echo differs from the decoded payload by one byte and the marker survives.
func TestUnionIgnoresANormalisedEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("q")
		// What a UTF-8 encoder does with a byte it cannot represent.
		normalised := strings.ToValidUTF8(value, "\uFFFD")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>result: %s</p></body></html>", normalised)
	}))
	defer server.Close()

	request, err := httpmsg.NewRequest("GET", server.URL+"/?q=hello")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	h := newHarness(t)
	response, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: response, Param: &params[0]}

	if findings := runRequestLevel(t, h, sqliUnion{}, target); len(findings) != 0 {
		t.Errorf("a normalised echo was reported: %v", findings[0].Evidence.Matches)
	}
}

// TestPercentDecodedHandlesBytesThatAreNotUTF8 pins the helper: the wide-byte quote is a byte
// sequence no UTF-8 decoder accepts, and a decoder that refuses it also refuses the echo.
func TestPercentDecodedHandlesBytesThatAreNotUTF8(t *testing.T) {
	got := percentDecoded("1%df%27+UNION")
	want := "1\xdf' UNION"
	if got != want {
		t.Errorf("percentDecoded = %q, want %q", got, want)
	}
	if percentDecoded("100%25 off") != "100% off" {
		t.Errorf("a literal percent was not handled: %q", percentDecoded("100%25 off"))
	}
	if percentDecoded("no escapes") != "no escapes" {
		t.Errorf("a plain value was changed: %q", percentDecoded("no escapes"))
	}
}
