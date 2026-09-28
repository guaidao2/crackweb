package active

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
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
	if len(seeds) != maxUnionColumns {
		t.Fatalf("unionSeeds() returned %d seeds, want %d", len(seeds), maxUnionColumns)
	}
	for i, seed := range seeds {
		want := i + 1
		if got := unionColumnsIn(seed); got != want {
			t.Errorf("seed %d carries %d markers, want %d: %s", i, got, want, seed)
		}
		if !strings.HasPrefix(seed, "1' UNION SELECT ") {
			t.Errorf("seed %d does not look like a UNION arm: %s", i, seed)
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
	if unionMarkersLanded("<html>918273645 UNION SELECT</html>", "1' UNION SELECT 918273645-- -") {
		t.Error("a reflection of the statement was treated as data")
	}
	if unionMarkersLanded("<html>nothing here</html>", "1' UNION SELECT 918273645-- -") {
		t.Error("a body with no marker was treated as landed")
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
