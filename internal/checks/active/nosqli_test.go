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

// nosqlConditionRe pulls the JS comparison out of an injected clause.
var nosqlConditionRe = regexp.MustCompile(`'?"?\s*([A-Za-z0-9_]+)\s*'?"?\s*==\s*'?"?\s*([A-Za-z0-9_]+)`)

// nosqlSite is a target with a $where-shaped flaw: the parameter reaches a
// condition the server evaluates, so its truth value decides the page.
//
// The comparison is evaluated rather than pattern-matched, so any two conditions
// with the same truth value answer identically — which is what a check reasoning
// about the server's semantics needs to be tested against.
func nosqlSite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("user")
		if q == "" {
			q = r.FormValue("user")
		}

		rows := 0
		switch {
		case strings.Contains(q, "admin"):
			rows = 1
		}

		// Then the appended clause, evaluated as a database would.
		if m := nosqlConditionRe.FindStringSubmatch(q); m != nil {
			op := "OR"
			if strings.Contains(q, "&&") {
				op = "AND"
			}
			equal := m[1] == m[2]
			switch {
			case op == "OR" && equal:
				rows = 40
			case op == "AND" && !equal:
				rows = 0
			}
		}

		body := "<html><body><form><input name=\"user\" value=\"" +
			strings.ReplaceAll(q, `"`, "&quot;") + "\"></form><table>"
		for i := 0; i < rows; i++ {
			body += "<tr><td>record</td></tr>"
		}
		body += "</table></body></html>"
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestNoSQLBooleanOracleFires: two spellings per truth value, and the two values
// are distinguishable.
func TestNoSQLBooleanOracleFires(t *testing.T) {
	server := nosqlSite(t)
	h := newHarness(t)

	request, err := httpmsg.NewRequest("GET", server.URL+"/find?user=admin")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	findings := (nosqli{}).Run(context.Background(), h.ctx, target)
	if len(findings) == 0 {
		t.Fatal("a real boolean oracle was not reported")
	}
	var sawOracle bool
	for _, f := range findings {
		if strings.Contains(strings.Join(f.Evidence.Matches, " "), "boolean oracle") {
			sawOracle = true
		}
	}
	if !sawOracle {
		t.Logf("findings: %+v", findings[0].Evidence.Matches)
	}
}

// TestNoSQLOracleIgnoresNoisyPage is the case the equivalence rule exists for: a
// page whose content follows the payload text rather than its truth value.
func TestNoSQLOracleIgnoresNoisyPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("user")
		// Every distinct payload produces a distinct page, but nothing is
		// evaluated — this is what an unsupported parameter looks like.
		fmt.Fprintf(w, "<html><body>no records for %s %s</body></html>",
			strings.ReplaceAll(q, `"`, "&quot;"), strings.Repeat("filler ", 40))
	}))
	defer server.Close()

	h := newHarness(t)
	request, _ := httpmsg.NewRequest("GET", server.URL+"/find?user=admin")
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	if findings := (nosqli{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		for _, f := range findings {
			for _, m := range f.Evidence.Matches {
				if strings.Contains(m, "boolean oracle") {
					t.Errorf("a page that only echoes the payload was reported as an oracle: %v", m)
				}
			}
		}
	}
}
