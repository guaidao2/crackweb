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

// orderBySite is a target whose sort parameter reaches the query.
//
// A valid term appended to the clause leaves the page alone; anything that
// breaks the statement produces an error page. That is the shape the check has
// to recognise, and the error page deliberately quotes the offending input, as
// real ones do.
func orderBySite(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order := r.URL.Query().Get("order")
		if order == "" {
			order = r.FormValue("order")
		}
		rows := strings.Repeat("<tr><td>row</td></tr>", 12)
		// The page does not echo the parameter: what matters is whether the
		// statement ran, and a fixed body keeps the two accepted forms exactly
		// comparable.
		if strings.ContainsAny(order, `'"`) {
			fmt.Fprintf(w, "<html><body><table>%s</table><p>unrecognized token</p></body></html>", rows)
			return
		}
		fmt.Fprintf(w, "<html><body><table>%s</table><p>sorted</p></body></html>", rows)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestSQLiOrderByFires(t *testing.T) {

	server := orderBySite(t)
	h := newHarness(t)
	request, err := httpmsg.NewRequest("GET", server.URL+"/list?order=desc")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	if findings := (sqliOrderBy{}).Run(context.Background(), h.ctx, target); len(findings) == 0 {
		t.Fatal("an injectable sort parameter was not reported")
	}
}

// TestSQLiOrderByIgnoresASafeTarget: a parameter that is only ever a value must
// produce nothing, however many terms are appended to it.
func TestSQLiOrderByIgnoresASafeTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The value is used, never concatenated: appending anything just changes
		// the text the page echoes.
		order := r.URL.Query().Get("order")
		fmt.Fprintf(w, "<html><body><table>%s</table><p>sorted by %s</p></body></html>",
			strings.Repeat("<tr><td>row</td></tr>", 12), strings.ReplaceAll(order, `"`, "&quot;"))
	}))
	defer server.Close()

	h := newHarness(t)
	request, _ := httpmsg.NewRequest("GET", server.URL+"/list?order=desc")
	baseline, err := h.client.Do(context.Background(), request)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	params := request.Params()
	target := &checks.Target{Request: request, Response: baseline, Param: &params[0]}

	if findings := (sqliOrderBy{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("a safe sort parameter was reported: %v", findings[0].Evidence.Matches)
	}
}
