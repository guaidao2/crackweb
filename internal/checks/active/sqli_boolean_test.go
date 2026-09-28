package active

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// conditionRe pulls the comparison out of an appended `AND`/`OR` clause.
var conditionRe = regexp.MustCompile(`(?i)(AND|OR)\s*'?"?\s*([A-Za-z0-9_]+)\s*'?"?\s*=\s*'?"?\s*([A-Za-z0-9_]+)`)

// booleanSite is a target with a genuine SQL-injection-shaped flaw: the
// parameter is concatenated into a WHERE clause, and the row count follows.
//
// The condition is *evaluated* rather than matched against a list of strings.
// That is what makes this harness worth having: it answers any two conditions
// with the same truth value identically and any two with different values
// differently, exactly as a database would — so a check that reasons about SQL
// semantics can be tested against it, and a check that pattern-matches cannot
// pass by accident.
func booleanSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("code")
		if q == "" {
			q = r.FormValue("code")
		}

		// Rows the un-injected query would return.
		rows := 0
		if strings.Contains(q, "WELCOME10") {
			rows = 1
		}

		// Then the appended condition, evaluated.
		if m := conditionRe.FindStringSubmatch(q); m != nil {
			op := strings.ToUpper(m[1])
			equal := strings.EqualFold(m[2], m[3])
			switch {
			case op == "OR" && equal:
				rows = 39 // always true, so the whole table
			case op == "OR" && !equal:
				// false term, so the base result stands
			case op == "AND" && !equal:
				rows = 0 // always false
			}
		}

		body := "<html><body><form><input name=\"code\" value=\"" +
			strings.ReplaceAll(q, `"`, "&quot;") + "\"></form><table>"
		for i := 0; i < rows; i++ {
			body += "<tr><td>coupon-row</td><td>10.0</td></tr>"
		}
		body += "</table></body></html>"
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestSQLiBooleanFiresOnAWidenedResultSet: an OR that widens the WHERE returns
// more than the baseline did, which is what a boolean channel looks like.
func TestSQLiBooleanFiresOnAWidenedResultSet(t *testing.T) {
	server := booleanSite(t)
	h := newHarness(t)

	request, _ := httpmsg.NewRequest("GET", server.URL+"/posts?code=WELCOME10")
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (sqliBoolean{}).Run(context.Background(), h.ctx, target)
	if len(findings) == 0 {
		t.Fatal("a widened result set was not reported")
	}
	t.Logf("reported: %v", findings[0].Evidence.Matches)
}

// TestSQLiBooleanIgnoresAShrinkingPage is the case observed on a real target.
//
// There, every OR wording produced a page that differed between the branches but
// was *smaller* than the baseline — the parameter was being rejected, not
// honoured. A query that has been widened cannot return less than it did before,
// so a shrinking page is not evidence, however reproducible the difference is.
func TestSQLiBooleanIgnoresAShrinkingPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("category")
		if strings.ContainsAny(q, `'"`) {
			// Any quote makes the page fail to a short, slightly-different page,
			// whichever condition follows.
			if strings.Contains(q, "'1'='1") {
				fmt.Fprint(w, "<html><body>No results for that category</body></html>")
				return
			}
			fmt.Fprint(w, "<html><body>No results. Try another category</body></html>")
			return
		}
		// The healthy page is large.
		fmt.Fprint(w, "<html><body>"+strings.Repeat("<article>post</article>", 400)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	request, _ := httpmsg.NewRequest("GET", server.URL+"/posts.php?category=pentest")
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (sqliBoolean{}).Run(context.Background(), h.ctx, target)
	if len(findings) != 0 {
		t.Errorf("a page that only shrank was reported: %v", findings[0].Evidence.Matches)
	}
}
