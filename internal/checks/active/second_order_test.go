package active

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/guaidao2/crackweb/internal/checks"
	"github.com/guaidao2/crackweb/internal/httpmsg"
)

// storedSite is a target with a store and a page that reads it back without
// escaping: the exact shape a second-order bug needs.
//
// The write is clean — it just appends what it was given. The read is where the
// stored value becomes a query, and where the payload finally does something.
func storedSite(t *testing.T) *httptest.Server {
	t.Helper()

	var (
		mu     sync.Mutex
		stored []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")

		if r.Method != "GET" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			// A real application parses the form before storing the value, so
			// the payload is stored decoded — `1%27` becomes `1'`. A harness
			// that stored the raw body would never reproduce the bug.
			values, _ := url.ParseQuery(string(body))
			mu.Lock()
			for _, list := range values {
				stored = append(stored, list...)
			}
			mu.Unlock()
			fmt.Fprint(w, "<html><body>Comment saved. "+strings.Repeat("thanks ", 30)+"</body></html>")
			return
		}

		// The read path: the stored values are concatenated straight into a
		// query, so a quote that arrived earlier breaks it now.
		mu.Lock()
		joined := strings.Join(stored, ",")
		mu.Unlock()

		if strings.ContainsAny(joined, `'"`) {
			fmt.Fprint(w, "<html><body>You have an error in your SQL syntax near the comment list</body></html>")
			return
		}
		fmt.Fprint(w, "<html><body>Comments: "+joined+" "+strings.Repeat("lorem ", 30)+"</body></html>")
	}))
	t.Cleanup(server.Close)
	return server
}

// TestSecondOrderFiresAfterStoring covers the whole technique: a write that
// looks harmless, and a read that breaks because of it.
func TestSecondOrderFiresAfterStoring(t *testing.T) {
	server := storedSite(t)
	h := newHarness(t)

	// The page that will read the stored value, visited before anything is
	// stored, so its healthy response can serve as the baseline.
	readRequest, err := httpmsg.NewRequest("GET", server.URL+"/comments")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	readBaseline, err := h.client.Do(context.Background(), readRequest)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if readBaseline.Status != 200 {
		t.Fatalf("baseline status = %d", readBaseline.Status)
	}

	h.ctx.Exchanges = func() []checks.Exchange {
		return []checks.Exchange{{Request: readRequest, Response: readBaseline}}
	}

	// The write, with the payload as its parameter value.
	writeRequest, err := httpmsg.NewRequest("POST", server.URL+"/comment")
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	writeRequest.Body = []byte("body=hello")
	writeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	writeRequest.Header.Set("Content-Length", "10")

	params := writeRequest.Params()
	if len(params) == 0 {
		t.Fatal("the write request has no parameters")
	}
	target := &checks.Target{Request: writeRequest, Response: readBaseline, Param: &params[0]}

	findings := secondOrder{}.Run(context.Background(), h.ctx, target)
	if len(findings) == 0 {
		t.Fatal("a stored payload that broke a later read was not reported")
	}

	f := findings[0]
	if f.CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89", f.CWE)
	}
	if len(f.Evidence.Matches) == 0 {
		t.Error("no evidence was recorded")
	}
	// The evidence has to name both halves of the relationship, or a reader
	// cannot tell which page was poisoned.
	joined := strings.Join(f.Evidence.Matches, " ")
	if !strings.Contains(joined, "/comment") || !strings.Contains(joined, "/comments") {
		t.Errorf("evidence does not name both the write and the read: %v", f.Evidence.Matches)
	}
}

// TestSecondOrderNeedsTraffic: with no store there is no second request to be
// second-order against, and the check must not invent one.
func TestSecondOrderNeedsTraffic(t *testing.T) {
	server := storedSite(t)
	h := newHarness(t)
	h.ctx.Exchanges = nil

	writeRequest, _ := httpmsg.NewRequest("POST", server.URL+"/comment")
	writeRequest.Body = []byte("body=hello")
	writeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	writeRequest.Header.Set("Content-Length", "10")
	params := writeRequest.Params()

	target := &checks.Target{Request: writeRequest, Param: &params[0]}
	if findings := (secondOrder{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("the check ran without any traffic to trigger with: %+v", findings)
	}
}

// TestSecondOrderIgnoresSafeMethods: a GET stores nothing.
func TestSecondOrderIgnoresSafeMethods(t *testing.T) {
	server := storedSite(t)
	h := newHarness(t)
	h.ctx.Exchanges = func() []checks.Exchange { return nil }

	request, _ := httpmsg.NewRequest("GET", server.URL+"/comments?body=hello")
	params := request.Params()
	target := &checks.Target{Request: request, Param: &params[0]}

	if findings := (secondOrder{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("a GET was treated as a write: %+v", findings)
	}
}

// TestSecondOrderStaysQuietOnAEscapingTarget is the other half: a store whose
// read path is safe must produce nothing, even though the write is identical.
func TestSecondOrderStaysQuietOnAEscapingTarget(t *testing.T) {
	var (
		mu     sync.Mutex
		stored []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method != "GET" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			values, _ := url.ParseQuery(string(body))
			mu.Lock()
			for _, list := range values {
				stored = append(stored, list...)
			}
			mu.Unlock()
			fmt.Fprint(w, "<html><body>Comment saved. "+strings.Repeat("thanks ", 30)+"</body></html>")
			return
		}
		mu.Lock()
		joined := strings.Join(stored, ",")
		mu.Unlock()
		// The read path escapes, so the stored payload stays inert.
		escaped := strings.NewReplacer("'", "&#39;", `"`, "&quot;").Replace(joined)
		fmt.Fprint(w, "<html><body>Comments: "+escaped+" "+strings.Repeat("lorem ", 30)+"</body></html>")
	}))
	defer server.Close()

	h := newHarness(t)
	readRequest, _ := httpmsg.NewRequest("GET", server.URL+"/comments")
	readBaseline, _ := h.client.Do(context.Background(), readRequest)
	h.ctx.Exchanges = func() []checks.Exchange {
		return []checks.Exchange{{Request: readRequest, Response: readBaseline}}
	}

	writeRequest, _ := httpmsg.NewRequest("POST", server.URL+"/comment")
	writeRequest.Body = []byte("body=hello")
	writeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	writeRequest.Header.Set("Content-Length", "10")
	params := writeRequest.Params()
	target := &checks.Target{Request: writeRequest, Response: readBaseline, Param: &params[0]}

	if findings := (secondOrder{}).Run(context.Background(), h.ctx, target); len(findings) != 0 {
		t.Errorf("a safe read path was reported: %+v", findings)
	}
}
